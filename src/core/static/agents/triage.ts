/**
 * TriageAndDedupAgent
 *
 * Deduplicates findings, assesses false positives using LLM reasoning,
 * and ranks findings by severity and confidence.
 */

import { streamResponse, type AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult, StaticFinding } from '../types';
import { createFindingTools, listFindingsDirect, getFindingStatsDirect } from '../tools/finding-tools';
import { createRepoTools } from '../tools/repo-tools';
import { saveState, appendToResultsJsonl, saveSubagentMessages } from '../workspace';
import fs from 'fs/promises';
import path from 'path';

const SYSTEM_PROMPT = `You are a security triage expert. Your job is to review security findings and:

1. DEDUPLICATE: Identify findings that represent the same vulnerability
2. ASSESS FALSE POSITIVES: Determine if findings are likely false positives by:
   - Reading the actual code
   - Checking if proper sanitization exists
   - Verifying if the dataflow is actually exploitable
3. RANK: Prioritize findings by severity and confidence

For each finding:
- If it's a duplicate, reject it with reason "duplicate of [other-id]"
- If it's a false positive, reject it with a clear explanation
- If it's valid, confirm it and optionally adjust confidence

Be conservative: when in doubt, keep the finding for manual review.`;

export interface TriageInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  abortSignal?: AbortSignal;
  onStepFinish?: (step: any) => void;
}

export async function runTriageAgent(input: TriageInput): Promise<StaticAgentResult> {
  const { paths, state, model, abortSignal, onStepFinish } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    const findingTools = createFindingTools(paths, 'triage');
    const repoTools = createRepoTools(paths);

    // Get all candidate findings
    const listResult = await listFindingsDirect(paths, { status: 'candidate' });

    if (!listResult.success || listResult.count === 0) {
      return {
        stage: 'triage',
        success: true,
        artifacts,
        summary: 'No candidate findings to triage',
        duration_ms: Date.now() - startTime,
      };
    }

    const tools = {
      list_findings: findingTools.list_findings,
      get_finding: findingTools.get_finding,
      check_duplicate: findingTools.check_duplicate,
      reject_finding: findingTools.reject_finding,
      confirm_finding: findingTools.confirm_finding,
      update_finding: findingTools.update_finding,
      read_file: repoTools.read_file,
    };

    const userPrompt = `Review and triage ${listResult.count} security findings.

For each finding:
1. Use get_finding to see full details
2. Use read_file to examine the actual code
3. Decide: confirm (valid vulnerability) or reject (false positive/duplicate)
4. Use confirm_finding or reject_finding appropriately

Start by listing all findings, then process them one by one.
Focus on high and critical severity first.`;

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

    // Get final stats
    const statsResult = await getFindingStatsDirect(paths);
    const stats = statsResult.success ? statsResult.stats : null;

    // Save triage summary
    const summaryPath = path.join(paths.artifacts.findings, 'triage_summary.json');
    await fs.writeFile(summaryPath, JSON.stringify({
      stats,
      timestamp: new Date().toISOString(),
    }, null, 2));
    artifacts.push(summaryPath);

    await saveState(paths, state);

    const savedMsgPath = await saveSubagentMessages(paths, 'triage', messages, {
      findings_processed: listResult.count,
      confirmed: stats?.byStatus.confirmed || 0,
      rejected: stats?.byStatus.rejected || 0,
    });
    artifacts.push(savedMsgPath);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'triage',
      success: true,
      duration_ms: Date.now() - startTime,
      findings_processed: listResult.count,
      stats,
    });

    return {
      stage: 'triage',
      success: true,
      artifacts,
      summary: `Triage complete: ${stats?.byStatus.confirmed || 0} confirmed, ${stats?.byStatus.rejected || 0} rejected from ${listResult.count} candidates`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'triage',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'triage',
      success: false,
      artifacts,
      summary: `Triage failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}
