/**
 * SpecSynthAgent
 *
 * Analyzes the codebase and synthesizes custom security rules:
 * - Semgrep rules tailored to the repo's patterns
 * - Joern taint queries for dataflow analysis
 * - Framework-specific security checks
 */

import { streamResponse, type AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult, RepoInventory } from '../types';
import { createRepoTools } from '../tools/repo-tools';
import { saveState, appendToResultsJsonl, saveSubagentMessages } from '../workspace';
import { generateTaintQuery } from '../external/joern';
import fs from 'fs/promises';
import path from 'path';
import { tool } from 'ai';
import { z } from 'zod';

const SYSTEM_PROMPT = `You are a security engineer specializing in static analysis rule creation. Your job is to analyze a codebase and generate custom security rules that are specific to this repository's patterns, frameworks, and coding conventions.

Your goals:
1. Identify security-relevant patterns unique to this codebase
2. Generate Semgrep rules that catch vulnerabilities specific to how this code is written
3. Create taint flow specifications for dangerous data flows

When generating Semgrep rules:
- Use the correct language mode (python, javascript, typescript, java, go, etc.)
- Make patterns specific enough to reduce false positives
- Include metavariables for capturing relevant code
- Add meaningful messages explaining the vulnerability
- Set appropriate severity (ERROR, WARNING, INFO)

Focus on:
- Authentication/authorization bypasses
- Injection vulnerabilities (SQL, command, template)
- Insecure deserialization
- Hardcoded secrets patterns specific to this repo
- Missing security controls (CSRF, rate limiting)
- Framework-specific misconfigurations

Be practical - generate rules that will find real issues, not theoretical ones.`;

export interface SpecSynthInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  abortSignal?: AbortSignal;
  onStepFinish?: (step: any) => void;
}

// Schema for saving Semgrep rules
const SaveSemgrepRuleSchema = z.object({
  ruleId: z.string().describe('Unique rule identifier (e.g., "custom-sql-injection-flask")'),
  language: z.string().describe('Target language (python, javascript, typescript, java, go, etc.)'),
  severity: z.enum(['ERROR', 'WARNING', 'INFO']).describe('Rule severity'),
  message: z.string().describe('Message explaining the vulnerability'),
  pattern: z.string().describe('Semgrep pattern to match'),
  patternNot: z.string().optional().describe('Pattern that should NOT match (for excluding safe cases)'),
  metavariablePattern: z.record(z.string(), z.string()).optional().describe('Additional metavariable constraints'),
  fix: z.string().optional().describe('Suggested fix pattern'),
  cwe: z.array(z.string()).optional().describe('CWE identifiers'),
  references: z.array(z.string()).optional().describe('Reference URLs'),
});

// Schema for saving taint specs
const SaveTaintSpecSchema = z.object({
  name: z.string().describe('Name for this taint specification'),
  sources: z.array(z.string()).describe('Function names that introduce tainted data'),
  sinks: z.array(z.string()).describe('Function names where tainted data is dangerous'),
  sanitizers: z.array(z.string()).optional().describe('Function names that sanitize data'),
  description: z.string().describe('Description of what this taint flow represents'),
});

export async function runSpecSynthAgent(input: SpecSynthInput): Promise<StaticAgentResult> {
  const { paths, state, model, abortSignal, onStepFinish } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    const specsDir = paths.artifacts.specs;
    const repoTools = createRepoTools(paths);

    // Get inventory info
    const inventory = state.inventory;
    if (!inventory) {
      return {
        stage: 'spec-synth',
        success: true,
        artifacts: [],
        summary: 'Spec synthesis skipped - no inventory available',
        duration_ms: Date.now() - startTime,
      };
    }

    // Track generated rules
    const generatedRules: any[] = [];
    const generatedTaintSpecs: any[] = [];

    // Create tools for rule generation
    const save_semgrep_rule = tool({
      description: 'Save a custom Semgrep rule to the specs directory',
      inputSchema: SaveSemgrepRuleSchema,
      execute: async (params: z.infer<typeof SaveSemgrepRuleSchema>) => {
        const rule = {
          id: params.ruleId,
          languages: [params.language],
          severity: params.severity,
          message: params.message,
          pattern: params.pattern,
          ...(params.patternNot && { pattern_not: params.patternNot }),
          ...(params.metavariablePattern && { metavariable_pattern: params.metavariablePattern }),
          ...(params.fix && { fix: params.fix }),
          metadata: {
            ...(params.cwe && { cwe: params.cwe }),
            ...(params.references && { references: params.references }),
            category: 'security',
            technology: [],
            generated_by: 'spec-synth-agent',
          },
        };

        generatedRules.push(rule);
        return { success: true, ruleId: params.ruleId, message: `Saved Semgrep rule: ${params.ruleId}` };
      },
    });

    const save_taint_spec = tool({
      description: 'Save a taint flow specification for Joern analysis',
      inputSchema: SaveTaintSpecSchema,
      execute: async (params: z.infer<typeof SaveTaintSpecSchema>) => {
        const query = generateTaintQuery(params.sources, params.sinks, params.sanitizers);
        const spec = {
          name: params.name,
          sources: params.sources,
          sinks: params.sinks,
          sanitizers: params.sanitizers || [],
          description: params.description,
          joernQuery: query,
        };

        generatedTaintSpecs.push(spec);
        return { success: true, name: params.name, message: `Saved taint spec: ${params.name}` };
      },
    });

    const tools = {
      list_files: repoTools.list_files,
      read_file: repoTools.read_file,
      search_code: repoTools.search_code,
      save_semgrep_rule,
      save_taint_spec,
    };

    // Build context from inventory
    const languageList = inventory.languages.map(l => `${l.name} (${Math.round(l.pct * 100)}%)`).join(', ');
    const frameworkHints = detectFrameworks(inventory);
    const hotspotSummary = inventory.security_hotspots.slice(0, 10).map(h => `- ${h.path}: ${h.reason}`).join('\n');

    const userPrompt = `Analyze this repository and generate custom security rules.

## Repository Profile
- Languages: ${languageList}
- Build systems: ${inventory.build_systems.join(', ') || 'none detected'}
- Framework hints: ${frameworkHints}

## Security Hotspots (top 10)
${hotspotSummary || 'None identified'}

## Your Tasks

1. **Examine the codebase patterns**
   - Use read_file to look at 3-5 security-relevant files from the hotspots
   - Identify authentication patterns, database access patterns, user input handling
   - Note any custom security utilities or wrappers

2. **Generate 3-5 Semgrep rules** specific to this codebase:
   - Look for patterns where security controls might be bypassed
   - Check for inconsistent use of security utilities
   - Find places where dangerous functions are used without proper validation

3. **Generate 1-2 taint specifications** for dataflow analysis:
   - Identify source functions (user input, request params, file reads)
   - Identify sink functions (SQL queries, command execution, file writes)
   - Include any sanitization functions used in the codebase

Focus on rules that will find REAL vulnerabilities in THIS specific codebase, not generic patterns.
Be creative - look for repo-specific anti-patterns.`;

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

    // Save generated rules to files
    if (generatedRules.length > 0) {
      const semgrepConfig = {
        rules: generatedRules,
      };
      const rulesPath = path.join(specsDir, 'custom-rules.yaml');
      await fs.writeFile(rulesPath, formatSemgrepYaml(semgrepConfig));
      artifacts.push(rulesPath);
    }

    if (generatedTaintSpecs.length > 0) {
      const taintSpecsPath = path.join(specsDir, 'taint-specs.json');
      await fs.writeFile(taintSpecsPath, JSON.stringify(generatedTaintSpecs, null, 2));
      artifacts.push(taintSpecsPath);

      // Also save Joern queries as .sc file
      const joernQueries = generatedTaintSpecs.map(s => `// ${s.name}: ${s.description}\n${s.joernQuery}`).join('\n\n');
      const joernPath = path.join(specsDir, 'custom-queries.sc');
      await fs.writeFile(joernPath, joernQueries);
      artifacts.push(joernPath);
    }

    // Save summary
    const summaryPath = path.join(specsDir, 'spec-synth-summary.json');
    await fs.writeFile(summaryPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      rules_generated: generatedRules.length,
      taint_specs_generated: generatedTaintSpecs.length,
      languages_analyzed: inventory.languages.map(l => l.name),
      hotspots_examined: inventory.security_hotspots.length,
    }, null, 2));
    artifacts.push(summaryPath);

    // Save agent messages
    const savedMsgPath = await saveSubagentMessages(paths, 'spec-synth', messages, {
      rules_generated: generatedRules.length,
      taint_specs_generated: generatedTaintSpecs.length,
    });
    artifacts.push(savedMsgPath);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'spec-synth',
      success: true,
      duration_ms: Date.now() - startTime,
      rules_generated: generatedRules.length,
      taint_specs_generated: generatedTaintSpecs.length,
    });

    return {
      stage: 'spec-synth',
      success: true,
      artifacts,
      summary: `Generated ${generatedRules.length} Semgrep rules and ${generatedTaintSpecs.length} taint specifications`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'spec-synth',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'spec-synth',
      success: false,
      artifacts,
      summary: `Spec synthesis failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * Detect likely frameworks from inventory
 */
function detectFrameworks(inventory: RepoInventory): string {
  const hints: string[] = [];
  const depFiles = inventory.dependency_files || [];
  const buildSystems = inventory.build_systems || [];

  // Python frameworks
  if (depFiles.some(f => f.includes('requirements') || f.includes('pyproject'))) {
    hints.push('Python (check for Flask/Django/FastAPI)');
  }

  // Node.js frameworks
  if (depFiles.includes('package.json')) {
    hints.push('Node.js (check for Express/Next.js/Fastify)');
  }

  // Java frameworks
  if (buildSystems.includes('maven') || buildSystems.includes('gradle')) {
    hints.push('Java (check for Spring/Jakarta)');
  }

  // Go frameworks
  if (depFiles.includes('go.mod')) {
    hints.push('Go (check for Gin/Echo/Fiber)');
  }

  return hints.join(', ') || 'unknown';
}

/**
 * Format Semgrep rules as YAML
 */
function formatSemgrepYaml(config: { rules: any[] }): string {
  // Simple YAML formatter for Semgrep rules
  let yaml = 'rules:\n';

  for (const rule of config.rules) {
    yaml += `  - id: ${rule.id}\n`;
    yaml += `    languages:\n`;
    for (const lang of rule.languages) {
      yaml += `      - ${lang}\n`;
    }
    yaml += `    severity: ${rule.severity}\n`;
    yaml += `    message: ${JSON.stringify(rule.message)}\n`;
    yaml += `    pattern: |\n`;
    for (const line of rule.pattern.split('\n')) {
      yaml += `      ${line}\n`;
    }
    if (rule.pattern_not) {
      yaml += `    pattern-not: |\n`;
      for (const line of rule.pattern_not.split('\n')) {
        yaml += `      ${line}\n`;
      }
    }
    if (rule.fix) {
      yaml += `    fix: ${JSON.stringify(rule.fix)}\n`;
    }
    yaml += `    metadata:\n`;
    yaml += `      category: security\n`;
    if (rule.metadata?.cwe) {
      yaml += `      cwe:\n`;
      for (const cwe of rule.metadata.cwe) {
        yaml += `        - ${cwe}\n`;
      }
    }
    yaml += '\n';
  }

  return yaml;
}
