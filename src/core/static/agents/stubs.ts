/**
 * Stub Agents
 *
 * Minimal implementations for agents that can be enhanced later:
 * - IndexGraphAgent: Currently a passthrough (index building is implicit in other tools)
 * - SpecSynthAgent: Reserved for custom query generation (future)
 * - VulRAGAgent: Reserved for vulnerability knowledge enrichment (needs DB)
 * - LocalizeAndProveAgent: Basic localization without complex trace reconstruction
 */

import { streamResponse, type AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult } from '../types';
import { createFindingTools, listFindingsDirect } from '../tools/finding-tools';
import { createRepoTools } from '../tools/repo-tools';
import { saveState, appendToResultsJsonl, saveSubagentMessages } from '../workspace';
import fs from 'fs/promises';
import path from 'path';

export interface StubAgentInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  abortSignal?: AbortSignal;
  onStepFinish?: (step: any) => void;
}

/**
 * IndexGraphAgent - Currently a passthrough
 *
 * Future: Build symbol index, call graph, import graph for navigation.
 * For now, we rely on the repo tools' search_code for navigation.
 */
export async function runIndexGraphAgent(input: StubAgentInput): Promise<StaticAgentResult> {
  const { paths, state } = input;
  const startTime = Date.now();

  try {
    // Create placeholder index files
    const indexDir = paths.artifacts.index;

    const placeholderIndex = {
      status: 'stub',
      note: 'Full index building not yet implemented. Using grep-based search.',
      timestamp: new Date().toISOString(),
    };

    await fs.writeFile(
      path.join(indexDir, 'symbols.json'),
      JSON.stringify(placeholderIndex, null, 2)
    );

    state.index = {
      symbol_index: path.join(indexDir, 'symbols.json'),
      call_graph: path.join(indexDir, 'call_graph.json'),
      import_graph: path.join(indexDir, 'import_graph.json'),
      dep_graph: path.join(indexDir, 'deps.json'),
      hotspot_ranking: state.inventory?.security_hotspots.map(h => h.path) || [],
    };

    await saveState(paths, state);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'index-graph',
      success: true,
      duration_ms: Date.now() - startTime,
      note: 'stub implementation',
    });

    return {
      stage: 'index-graph',
      success: true,
      artifacts: [path.join(indexDir, 'symbols.json')],
      summary: 'Index stage complete (using search-based navigation)',
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      stage: 'index-graph',
      success: false,
      artifacts: [],
      summary: `Index stage failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * SpecSynthAgent - Currently a passthrough
 *
 * Future: Generate custom Semgrep rules, CodeQL queries, and taint specs
 * based on the codebase patterns.
 */
export async function runSpecSynthAgent(input: StubAgentInput): Promise<StaticAgentResult> {
  const { paths, state } = input;
  const startTime = Date.now();

  try {
    const specsDir = paths.artifacts.specs;

    const placeholderSpecs = {
      status: 'stub',
      note: 'Custom spec synthesis not yet implemented. Using default tool rules.',
      timestamp: new Date().toISOString(),
      planned_features: [
        'Custom taint source/sink detection',
        'Repo-specific Semgrep rules',
        'CodeQL query generation',
      ],
    };

    await fs.writeFile(
      path.join(specsDir, 'custom_specs.json'),
      JSON.stringify(placeholderSpecs, null, 2)
    );

    await saveState(paths, state);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'spec-synth',
      success: true,
      duration_ms: Date.now() - startTime,
      note: 'stub implementation',
    });

    return {
      stage: 'spec-synth',
      success: true,
      artifacts: [path.join(specsDir, 'custom_specs.json')],
      summary: 'Spec synthesis stage complete (using default rules)',
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      stage: 'spec-synth',
      success: false,
      artifacts: [],
      summary: `Spec synthesis failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * VulRAGAgent - Passthrough stub
 *
 * Future: Enrich findings with:
 * - Similar vulnerabilities from CWE database
 * - Historical fix patterns
 * - Remediation recommendations
 *
 * Requires: Vulnerability knowledge base (user to provide)
 */
export async function runVulRAGAgent(input: StubAgentInput): Promise<StaticAgentResult> {
  const { paths, state } = input;
  const startTime = Date.now();

  try {
    // For now, just pass through without enrichment
    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'vul-rag',
      success: true,
      duration_ms: Date.now() - startTime,
      note: 'stub implementation - waiting for vulnerability knowledge base',
    });

    return {
      stage: 'vul-rag',
      success: true,
      artifacts: [],
      summary: 'VulRAG stage skipped (knowledge base not configured)',
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      stage: 'vul-rag',
      success: false,
      artifacts: [],
      summary: `VulRAG failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * LocalizeAndProveAgent
 *
 * Uses LLM to examine findings and add precise localization with code context.
 */
export async function runLocalizeAgent(input: StubAgentInput): Promise<StaticAgentResult> {
  const { paths, state, model, abortSignal, onStepFinish } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    const findingTools = createFindingTools(paths, 'localize');
    const repoTools = createRepoTools(paths);

    // Get candidate findings
    const listResult = await listFindingsDirect(paths, { status: 'candidate' });

    if (!listResult.success || listResult.count === 0) {
      return {
        stage: 'localize',
        success: true,
        artifacts,
        summary: 'No findings to localize',
        duration_ms: Date.now() - startTime,
      };
    }

    const tools = {
      list_findings: findingTools.list_findings,
      get_finding: findingTools.get_finding,
      update_finding: findingTools.update_finding,
      read_file: repoTools.read_file,
      search_code: repoTools.search_code,
    };

    const systemPrompt = `You are a security analyst. Your job is to examine security findings and:
1. Read the code at the reported location
2. Trace the data flow if applicable
3. Add precise location details
4. Update the finding with a clear trace summary

For each finding, update it with:
- A clear path_summary describing the vulnerability
- Confidence adjustment based on code review
- Additional tags if relevant`;

    const userPrompt = `Review ${listResult.count} findings and localize them.

For each finding:
1. Use get_finding to see details
2. Use read_file to examine the code
3. Use update_finding to add trace information

Process high-severity findings first.`;

    const result = streamResponse({
      model,
      system: systemPrompt,
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

    const savedMsgPath = await saveSubagentMessages(paths, 'localize', messages, {
      findings_processed: listResult.count,
    });
    artifacts.push(savedMsgPath);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'localize',
      success: true,
      duration_ms: Date.now() - startTime,
      findings_processed: listResult.count,
    });

    return {
      stage: 'localize',
      success: true,
      artifacts,
      summary: `Localization complete: ${listResult.count} findings processed`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'localize',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'localize',
      success: false,
      artifacts,
      summary: `Localization failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}
