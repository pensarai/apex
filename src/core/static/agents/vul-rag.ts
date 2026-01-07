/**
 * VulRAGAgent - Vulnerability Knowledge Enrichment
 *
 * Enriches security findings with CVE/CWE data from local Nuclei templates.
 * Uses the Nuclei template repository to:
 * - Map CWE IDs to known CVEs and exploits
 * - Provide real-world severity calibration
 * - Extract remediation guidance
 * - Identify similar vulnerability patterns
 */

import { streamResponse, type AIModel } from '../../ai';
import { tool } from 'ai';
import { z } from 'zod';
import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult, StaticFinding } from '../types';
import {
  createFindingTools,
  listFindingsDirect,
  getFindingDirect,
  updateFindingDirect,
} from '../tools/finding-tools';
import { appendToResultsJsonl, saveSubagentMessages } from '../workspace';
import {
  initializeNucleiTemplates,
  searchTemplates,
  getTemplate,
  getTemplateContent,
  getIndexStats,
  type NucleiTemplate,
  type NucleiSearchQuery,
} from '../external/nuclei';
import fs from 'fs/promises';
import path from 'path';

// ============================================================================
// System Prompt
// ============================================================================

const SYSTEM_PROMPT = `You are a security researcher enriching vulnerability findings with real-world threat intelligence from the Nuclei template database.

Your job is to enhance each finding with:

## 1. CVE/CWE Correlation
- Search Nuclei templates by CWE ID to find related CVEs
- Look for templates matching the software/framework in the finding
- Identify patterns that match the vulnerability type

## 2. Severity Calibration
- Compare the finding's severity against real-world CVEs
- If Nuclei templates show the CWE is commonly exploited, increase confidence
- If templates show it requires specific conditions, note them

## 3. Remediation Guidance
- Extract remediation advice from matching templates
- Note common fix patterns for the vulnerability type
- Identify any framework-specific mitigations

## 4. Risk Assessment
- Determine if there are public exploits for similar vulnerabilities
- Note if the vulnerability type is commonly targeted
- Add relevant tags based on Nuclei template metadata

When updating findings:
- Add "cve-enriched" tag if you found related CVEs
- Add CVE IDs to the finding's evidence/notes
- Include remediation guidance in the fix_summary
- Adjust confidence based on whether templates exist for this vuln type`;

// ============================================================================
// Tool Schemas
// ============================================================================

const SearchNucleiSchema = z.object({
  cwe: z.array(z.string()).optional().describe('CWE IDs to search for (e.g., ["CWE-89", "CWE-79"])'),
  tags: z.array(z.string()).optional().describe('Tags to search for (e.g., ["apache", "rce", "wordpress"])'),
  severity: z.array(z.enum(['critical', 'high', 'medium', 'low', 'info'])).optional(),
  text: z.string().optional().describe('Text search in template name/description'),
  limit: z.number().optional().default(10).describe('Max results to return'),
});

const GetTemplateDetailsSchema = z.object({
  templateId: z.string().describe('Nuclei template ID to retrieve'),
});

const GetTemplateContentSchema = z.object({
  templateId: z.string().describe('Template ID to get full YAML content for'),
});

// ============================================================================
// Nuclei Tools
// ============================================================================

function createNucleiTools() {
  /**
   * Search Nuclei templates
   */
  const search_nuclei = tool({
    description: 'Search Nuclei vulnerability templates by CWE, tags, severity, or text',
    inputSchema: SearchNucleiSchema,
    execute: async ({ cwe, tags, severity, text, limit }: z.infer<typeof SearchNucleiSchema>) => {
      try {
        const query: NucleiSearchQuery = {
          cwe,
          tags,
          severity,
          text,
          limit: limit || 10,
        };

        const result = await searchTemplates(query);

        return {
          success: true,
          totalMatches: result.totalMatches,
          templates: result.templates.map(t => ({
            id: t.id,
            name: t.name,
            severity: t.severity,
            cwe: t.cwe,
            cve: t.cve,
            tags: t.tags.slice(0, 10), // Limit tags in response
            description: t.description?.slice(0, 200), // Truncate description
            remediation: t.remediation?.slice(0, 300),
          })),
        };
      } catch (error: any) {
        return {
          success: false,
          error: `Failed to search templates: ${error.message}`,
          templates: [],
        };
      }
    },
  });

  /**
   * Get template details
   */
  const get_template = tool({
    description: 'Get full details of a specific Nuclei template',
    inputSchema: GetTemplateDetailsSchema,
    execute: async ({ templateId }: z.infer<typeof GetTemplateDetailsSchema>) => {
      try {
        const template = await getTemplate(templateId);

        if (!template) {
          return { success: false, error: `Template not found: ${templateId}` };
        }

        return {
          success: true,
          template: {
            id: template.id,
            name: template.name,
            severity: template.severity,
            cwe: template.cwe,
            cve: template.cve,
            tags: template.tags,
            description: template.description,
            remediation: template.remediation,
            references: template.references,
            author: template.author,
          },
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  /**
   * Get template YAML content
   */
  const get_template_content = tool({
    description: 'Get the full YAML content of a Nuclei template (for understanding exploit patterns)',
    inputSchema: GetTemplateContentSchema,
    execute: async ({ templateId }: z.infer<typeof GetTemplateContentSchema>) => {
      try {
        const template = await getTemplate(templateId);
        if (!template) {
          return { success: false, error: `Template not found: ${templateId}` };
        }

        const content = await getTemplateContent(template);
        if (!content) {
          return { success: false, error: 'Failed to read template content' };
        }

        // Truncate very long templates
        const truncated = content.length > 5000 ? content.slice(0, 5000) + '\n...[truncated]' : content;

        return {
          success: true,
          templateId,
          content: truncated,
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  return {
    search_nuclei,
    get_template,
    get_template_content,
  };
}

// ============================================================================
// Agent Input/Output
// ============================================================================

export interface VulRAGInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  abortSignal?: AbortSignal;
  onStepFinish?: (step: any) => void;
}

// ============================================================================
// Agent Implementation
// ============================================================================

/**
 * Run the VulRAG agent to enrich findings with Nuclei template data
 */
export async function runVulRAGAgent(input: VulRAGInput): Promise<StaticAgentResult> {
  const { paths, state, model, abortSignal, onStepFinish } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    // Initialize Nuclei templates (clone if needed, update if stale)
    console.log('Initializing Nuclei templates...');
    const index = await initializeNucleiTemplates({ skipUpdate: true });

    const stats = await getIndexStats();
    console.log(`Nuclei index ready: ${stats?.total || index.templates_count} templates`);

    // Get candidate findings
    const listResult = await listFindingsDirect(paths, { status: 'candidate' });

    if (!listResult.success || listResult.count === 0) {
      await appendToResultsJsonl(paths, {
        type: 'agent_complete',
        agent: 'vul-rag',
        success: true,
        duration_ms: Date.now() - startTime,
        note: 'No candidate findings to enrich',
      });

      return {
        stage: 'vul-rag',
        success: true,
        artifacts,
        summary: 'No candidate findings to enrich',
        duration_ms: Date.now() - startTime,
      };
    }

    // Create tools
    const findingTools = createFindingTools(paths, 'vul-rag');
    const nucleiTools = createNucleiTools();

    const tools = {
      list_findings: findingTools.list_findings,
      get_finding: findingTools.get_finding,
      update_finding: findingTools.update_finding,
      search_nuclei: nucleiTools.search_nuclei,
      get_template: nucleiTools.get_template,
      get_template_content: nucleiTools.get_template_content,
    };

    // Build finding summaries for prompt
    const findingSummaries = listResult.findings
      .slice(0, 15) // Limit to top 15 findings
      .map(f => `- [${f.severity.toUpperCase()}] ${f.id}: ${f.title}\n  CWE: ${f.cwe.join(', ')}`)
      .join('\n');

    // Get top CWEs from findings for batch search
    const allCwes = new Set<string>();
    for (const f of listResult.findings) {
      for (const cwe of f.cwe) {
        allCwes.add(cwe);
      }
    }
    const topCwes = Array.from(allCwes).slice(0, 10);

    const userPrompt = `Enrich ${listResult.count} security findings with Nuclei vulnerability intelligence.

## Nuclei Database Status
- Total templates: ${stats?.total || index.templates_count}
- Templates by severity: ${JSON.stringify(stats?.bySeverity || {})}

## Findings to Enrich
${findingSummaries}

## CWEs to Research
These CWEs appear in the findings: ${topCwes.join(', ')}

## Your Tasks

1. **Search by CWE**: Use search_nuclei to find templates for each unique CWE in the findings
   - Start with the most common CWEs
   - Note which CWEs have many templates (commonly exploited) vs few

2. **Research Templates**: For interesting matches, use get_template to see details
   - Look for CVE references
   - Extract remediation guidance
   - Note severity patterns

3. **Enrich Findings**: Use update_finding to add intelligence
   - Add "cve-enriched" tag if you found relevant CVEs
   - Add related CVE IDs to additionalEvidence
   - Update fixSummary with remediation from templates
   - Adjust confidence if templates show this is commonly exploited

4. **Priority**: Focus on high/critical severity findings first

Be efficient - batch CWE searches where possible and focus on findings that benefit most from enrichment.`;

    // Run the agent
    const result = streamResponse({
      model,
      system: SYSTEM_PROMPT,
      prompt: userPrompt,
      tools,
      abortSignal,
      onStepFinish,
    });

    const messages: any[] = [];
    for await (const chunk of result.fullStream) {
      if (chunk.type === 'tool-result' || chunk.type === 'text-delta') {
        messages.push(chunk);
      }
    }

    // Save enrichment summary
    const enrichmentSummary = {
      findings_processed: listResult.count,
      cwes_researched: topCwes,
      nuclei_templates_available: stats?.total || index.templates_count,
      timestamp: new Date().toISOString(),
    };

    const summaryPath = path.join(paths.artifacts.findings, 'vulrag_enrichment.json');
    await fs.writeFile(summaryPath, JSON.stringify(enrichmentSummary, null, 2));
    artifacts.push(summaryPath);

    // Save conversation
    const savedMsgPath = await saveSubagentMessages(paths, 'vul-rag', messages, {
      findings_processed: listResult.count,
      cwes_researched: topCwes.length,
    });
    artifacts.push(savedMsgPath);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'vul-rag',
      success: true,
      duration_ms: Date.now() - startTime,
      findings_processed: listResult.count,
      cwes_researched: topCwes,
    });

    return {
      stage: 'vul-rag',
      success: true,
      artifacts,
      summary: `VulRAG enrichment complete: ${listResult.count} findings processed, ${topCwes.length} CWEs researched`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'vul-rag',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'vul-rag',
      success: false,
      artifacts,
      summary: `VulRAG failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

// ============================================================================
// Direct Enrichment Helper (for non-AI batch processing)
// ============================================================================

/**
 * Directly enrich a finding with Nuclei data (no AI agent)
 * Useful for batch processing or when AI enrichment is not needed
 */
export async function enrichFindingDirect(
  paths: WorkspacePaths,
  findingId: string
): Promise<{ success: boolean; enriched: boolean; cves?: string[]; error?: string }> {
  try {
    // Get the finding
    const { success, finding, error } = await getFindingDirect(paths, findingId);
    if (!success || !finding) {
      return { success: false, enriched: false, error };
    }

    // Search for related templates
    const searchResult = await searchTemplates({
      cwe: finding.cwe,
      limit: 5,
    });

    if (searchResult.templates.length === 0) {
      return { success: true, enriched: false };
    }

    // Extract CVEs from templates
    const relatedCves: string[] = [];
    const remediations: string[] = [];

    for (const template of searchResult.templates) {
      if (template.cve) {
        relatedCves.push(...template.cve);
      }
      if (template.remediation) {
        remediations.push(template.remediation);
      }
    }

    // Update the finding with enrichment data
    const tags = ['cve-enriched'];
    if (relatedCves.length > 0) {
      tags.push(`cves:${relatedCves.length}`);
    }

    const additionalEvidence = relatedCves.length > 0
      ? `Related CVEs from Nuclei: ${relatedCves.slice(0, 5).join(', ')}`
      : `Found ${searchResult.templates.length} related Nuclei templates`;

    await updateFindingDirect(paths, findingId, {
      tags,
      additionalEvidence,
    });

    return {
      success: true,
      enriched: true,
      cves: relatedCves.slice(0, 10),
    };
  } catch (error: any) {
    return { success: false, enriched: false, error: error.message };
  }
}
