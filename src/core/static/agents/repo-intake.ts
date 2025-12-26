/**
 * RepoIntakeAgent
 *
 * First agent in the pipeline. Analyzes the repository structure and creates
 * an inventory of languages, build systems, and security hotspots.
 */

import { streamResponse, type AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type {
  StaticAnalysisState,
  StaticAgentResult,
  RepoInventory,
  ToolAvailability,
} from '../types';
import { createRepoTools } from '../tools/repo-tools';
import { saveState, appendToResultsJsonl, saveSubagentMessages } from '../workspace';
import fs from 'fs/promises';
import path from 'path';

const SYSTEM_PROMPT = `You are a repository analysis agent. Your job is to analyze a git repository and create a comprehensive inventory of its contents.

Your tasks:
1. Detect all programming languages used in the repository
2. Identify build systems and package managers
3. Find dependency manifest files
4. Locate security-sensitive files and code patterns (auth, crypto, file ops, etc.)
5. Recommend which analysis backends should be used

Be thorough but efficient. Focus on files that matter for security analysis.

After analysis, provide a structured summary of your findings.`;

export interface RepoIntakeInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  toolAvailability: ToolAvailability;
  abortSignal?: AbortSignal;
  onStepFinish?: (step: any) => void;
}

export async function runRepoIntakeAgent(
  input: RepoIntakeInput
): Promise<StaticAgentResult> {
  const { paths, state, model, toolAvailability, abortSignal, onStepFinish } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    // Create tools
    const tools = createRepoTools(paths);

    // Build user prompt
    const userPrompt = `Analyze the repository at: ${paths.repo}

Please:
1. Use detect_languages to identify programming languages
2. Use detect_build_systems to find build tools and dependency files
3. Use find_security_hotspots to locate security-sensitive code
4. Use list_files to get an overview of the repository structure

After gathering this information, provide a summary of:
- Main languages and their percentages
- Build systems detected
- Key security-sensitive areas to focus analysis on
- Recommended analysis tools based on languages (semgrep, codeql, joern)

Available tools: ${Object.keys(toolAvailability).filter(k => (toolAvailability as any)[k].available).join(', ')}`;

    // Run the agent
    const result = streamResponse({
      model,
      system: SYSTEM_PROMPT,
      prompt: userPrompt,
      tools,
      abortSignal,
      onStepFinish,
    });

    // Collect messages for saving
    const messages: any[] = [];
    for await (const chunk of result.fullStream) {
      if (chunk.type === 'tool-result' || chunk.type === 'text-delta') {
        messages.push(chunk);
      }
    }

    // Parse results from tool calls
    let languagesResult: any = null;
    let buildSystemsResult: any = null;
    let hotspotsResult: any = null;

    for (const msg of messages) {
      if (msg.toolResults) {
        for (const tr of msg.toolResults) {
          if (tr.toolName === 'detect_languages') {
            languagesResult = tr.result;
          } else if (tr.toolName === 'detect_build_systems') {
            buildSystemsResult = tr.result;
          } else if (tr.toolName === 'find_security_hotspots') {
            hotspotsResult = tr.result;
          }
        }
      }
    }

    // Build inventory
    const inventory: RepoInventory = {
      languages: languagesResult?.languages || [],
      build_systems: buildSystemsResult?.buildSystems || [],
      dependency_files: buildSystemsResult?.dependencyFiles || [],
      security_hotspots: hotspotsResult?.hotspots || [],
      recommended_backends: {
        semgrep: true, // Always recommend Semgrep
        codeql: {
          enabled: toolAvailability.codeql.available,
          languages: languagesResult?.languages
            ?.filter((l: any) => ['python', 'javascript', 'typescript', 'java', 'go', 'ruby', 'csharp', 'cpp'].includes(l.name))
            .map((l: any) => l.name) || [],
        },
        joern: {
          enabled: toolAvailability.joern.available,
          languages: languagesResult?.languages
            ?.filter((l: any) => ['c', 'cpp', 'java', 'javascript', 'python'].includes(l.name))
            .map((l: any) => l.name) || [],
        },
        secrets: toolAvailability.trufflehog.available,
        dependencies: true,
      },
      exclude_patterns: ['node_modules', 'vendor', '.git', '__pycache__', 'dist', 'build'],
    };

    // Save inventory
    const inventoryPath = path.join(paths.artifacts.inventory, 'repo_inventory.json');
    await fs.writeFile(inventoryPath, JSON.stringify(inventory, null, 2));
    artifacts.push(inventoryPath);

    // Update state
    state.inventory = inventory;
    await saveState(paths, state);

    // Save agent messages
    const savedMsgPath = await saveSubagentMessages(paths, 'repo-intake', messages, {
      languages: inventory.languages.length,
      hotspots: inventory.security_hotspots.length,
    });
    artifacts.push(savedMsgPath);

    // Log completion
    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'repo-intake',
      success: true,
      duration_ms: Date.now() - startTime,
      languages_found: inventory.languages.length,
      hotspots_found: inventory.security_hotspots.length,
    });

    const primaryLangs = inventory.languages.slice(0, 3).map(l => l.name).join(', ');

    return {
      stage: 'repo-intake',
      success: true,
      artifacts,
      summary: `Repository analyzed: ${inventory.languages.length} languages (${primaryLangs}), ${inventory.security_hotspots.length} security hotspots identified`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'repo-intake',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'repo-intake',
      success: false,
      artifacts,
      summary: `Repository analysis failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}
