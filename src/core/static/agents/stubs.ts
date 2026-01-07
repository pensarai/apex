/**
 * Agent Implementations
 *
 * Real implementations for the static analysis agents.
 * LocalizeAgent performs dataflow analysis to enhance findings.
 */

import { streamResponse, type AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult } from '../types';
import { createFindingTools, listFindingsDirect, getFindingDirect } from '../tools/finding-tools';
import { createRepoTools } from '../tools/repo-tools';
import { saveState, appendToResultsJsonl, saveSubagentMessages } from '../workspace';
import fs from 'fs/promises';
import path from 'path';

// Re-export real implementations
export { runIndexGraphAgent } from './index-graph';
export { runSpecSynthAgent } from './spec-synth';

export interface StubAgentInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  abortSignal?: AbortSignal;
  onStepFinish?: (step: any) => void;
}

const LOCALIZE_SYSTEM_PROMPT = `You are an expert security analyst performing precise vulnerability localization and dataflow analysis. Your job is to examine security findings from static analysis tools and enhance them with detailed trace information.

For each finding you analyze:

## 1. Code Examination
- Read the vulnerable code at the reported location
- Understand the context: what function is this in? What does it do?
- Identify the actual security issue vs false positives

## 2. Dataflow Tracing
- **Source**: Where does the untrusted data originate? (user input, file read, network request, etc.)
- **Propagation**: How does the data flow through the code? Follow variable assignments, function calls, returns
- **Sink**: Where does the dangerous operation occur? (SQL query, command execution, file write, etc.)
- **Sanitization**: Are there any sanitization/validation steps? Are they sufficient?

## 3. Exploitability Assessment
Consider:
- Can an attacker control the source data?
- Is the dataflow actually reachable in practice?
- Are there runtime protections (WAF, sandboxing) that might mitigate?
- What's the actual impact if exploited?

## 4. Confidence Calibration
Adjust confidence based on your analysis:
- **Increase** if: clear dataflow, no sanitization, easily exploitable
- **Decrease** if: sanitization present, complex conditions needed, limited impact
- **Reject** if: false positive (data is never user-controlled, proper sanitization exists)

When updating findings, provide:
- Clear path_summary describing source → sink flow in plain English
- Specific code references for source and sink locations
- Confidence adjustment with reasoning
- Relevant tags (e.g., "user-controlled", "authenticated-only", "internal-api")`;

/**
 * LocalizeAndProveAgent
 *
 * Examines findings from static analysis tools and enhances them with:
 * - Precise source/sink localization
 * - Dataflow trace narratives
 * - Confidence calibration based on code review
 * - Exploitability assessment
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

    // Get high-priority findings for detailed analysis
    const highPriorityFindings = listResult.findings
      ?.filter(f => f.severity === 'critical' || f.severity === 'high')
      .slice(0, 10) || [];

    const mediumFindings = listResult.findings
      ?.filter(f => f.severity === 'medium')
      .slice(0, 5) || [];

    const findingsToAnalyze = [...highPriorityFindings, ...mediumFindings];

    // Build finding summaries for the prompt
    const findingSummaries = await Promise.all(
      findingsToAnalyze.map(async f => {
        const detail = await getFindingDirect(paths, f.id);
        if (!detail.success || !detail.finding) return null;
        return {
          id: f.id,
          title: f.title,
          severity: f.severity,
          file: f.file,
          line: f.line,
          cwe: f.cwe,
          description: detail.finding.description,
          toolEvidence: detail.finding.evidence?.[0]?.tool,
        };
      })
    );

    const validFindings = findingSummaries.filter(f => f !== null);

    if (validFindings.length === 0) {
      return {
        stage: 'localize',
        success: true,
        artifacts,
        summary: 'No findings available for detailed analysis',
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

    const findingsList = validFindings.map(f =>
      `- [${f!.severity.toUpperCase()}] ${f!.id}: ${f!.title}\n  File: ${f!.file}:${f!.line}\n  CWE: ${f!.cwe.join(', ')}`
    ).join('\n');

    const userPrompt = `Analyze and localize the following ${validFindings.length} security findings.

## Findings to Analyze
${findingsList}

## Your Tasks

For each finding (prioritize critical/high severity):

1. **Use get_finding** to see full details including tool evidence

2. **Use read_file** to examine:
   - The vulnerable code location (±20 lines for context)
   - Related files if the dataflow spans multiple files
   - Any security utilities or validators referenced

3. **Use search_code** to:
   - Find the source of user input (search for request parameters, form data, etc.)
   - Locate sanitization functions that might be applied
   - Find similar patterns elsewhere in the codebase

4. **Use update_finding** to enhance each finding with:
   - \`pathSummary\`: Clear description of the dataflow (e.g., "User input from request.GET['id'] flows to cursor.execute() without sanitization")
   - \`confidence\`: Adjusted score (0.0-1.0) based on your analysis
   - \`tags\`: Add relevant tags like "user-controlled", "requires-auth", "internal-only"
   - \`additionalEvidence\`: Key code snippets showing the vulnerability

5. If a finding is a **false positive**, use update_finding with:
   - \`status\`: "rejected"
   - \`rejectionReason\`: Clear explanation why it's not exploitable

Be thorough but efficient. Focus on findings that are likely real vulnerabilities.`;

    const result = streamResponse({
      model,
      system: LOCALIZE_SYSTEM_PROMPT,
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
      findings_analyzed: validFindings.length,
      total_candidates: listResult.count,
    });
    artifacts.push(savedMsgPath);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'localize',
      success: true,
      duration_ms: Date.now() - startTime,
      findings_analyzed: validFindings.length,
    });

    return {
      stage: 'localize',
      success: true,
      artifacts,
      summary: `Localization complete: ${validFindings.length} findings analyzed in detail`,
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
