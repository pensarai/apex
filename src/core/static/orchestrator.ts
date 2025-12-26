/**
 * Static Analysis Orchestrator
 *
 * Sequences the 8-agent pipeline for LLM-augmented SAST:
 * 1. RepoIntake - Analyze repository structure
 * 2. IndexGraph - Build code navigation index
 * 3. Analyzer - Run static analysis tools (parallel internally)
 * 4. SpecSynth - Synthesize custom rules
 * 5. VulRAG - Enrich with vulnerability knowledge
 * 6. Localize - Precise localization with traces
 * 7. Triage - Deduplicate and rank findings
 * 8. Report - Generate final reports
 *
 * Follows the same pattern as runPentestOrchestrator():
 * - pLimit for concurrency control
 * - Callbacks for progress/spawn/stream/complete events
 * - JSONL logging for incremental results
 */

import { execSync } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import pLimit from 'p-limit';
import type { AIModel } from '../ai';
import { Session } from '../session';
import { generateRandomName } from '../../util/name';
import { detectAvailableTools, hasMinimumTools, getInstallInstructions } from './external/detector';
import {
  createWorkspace,
  saveState,
  loadState,
  appendToResultsJsonl,
  type WorkspacePaths,
} from './workspace';
import type {
  StaticAnalysisState,
  StaticOrchestratorInput,
  StaticOrchestratorResult,
  StaticAnalysisProgress,
  StaticSubagentSpawnInfo,
  StaticSubagentStreamEvent,
  StaticAgentResult,
  StaticFinding,
  StaticAnalysisStage,
  ToolAvailability,
} from './types';
import { STAGE_ORDER, STAGE_NAMES, AGENT_TIMEOUTS } from './types';

// Agent imports
import {
  runRepoIntakeAgent,
  runIndexGraphAgent,
  runAnalyzerAgent,
  runSpecSynthAgent,
  runVulRAGAgent,
  runLocalizeAgent,
  runTriageAgent,
  runReportAgent,
} from './agents';

/** Default concurrency limit for parallel stages */
const DEFAULT_CONCURRENCY_LIMIT = 3;

/**
 * Run the static analysis orchestrator
 *
 * Sequences 8 agents to analyze a git repository for security vulnerabilities.
 */
export async function runStaticOrchestrator(
  input: StaticOrchestratorInput
): Promise<StaticOrchestratorResult> {
  const {
    repoPath,
    repoUrl,
    ref = 'HEAD',
    model,
    sessionConfig,
    onProgress,
    onAgentSpawn,
    onAgentStream,
    onAgentComplete,
    abortSignal,
    concurrencyLimit = DEFAULT_CONCURRENCY_LIMIT,
  } = input;

  const startTime = Date.now();

  // Report progress helper
  const reportProgress = (
    phase: StaticAnalysisProgress['phase'],
    message: string,
    extras: Partial<StaticAnalysisProgress> = {}
  ) => {
    onProgress?.({
      phase,
      message,
      totalStages: 8,
      ...extras,
    });
  };

  reportProgress('starting', 'Initializing static analysis...');

  // =========================================================================
  // Step 1: Detect available tools
  // =========================================================================
  reportProgress('starting', 'Detecting available analysis tools...');
  const toolAvailability = await detectAvailableTools();

  if (!hasMinimumTools(toolAvailability)) {
    const instructions = getInstallInstructions(toolAvailability);
    throw new Error(
      `Minimum tools not available. Please install:\n${instructions.join('\n')}`
    );
  }

  // =========================================================================
  // Step 2: Resolve git info and create workspace
  // =========================================================================
  reportProgress('starting', 'Setting up workspace...');

  // Resolve commit SHA
  let commitSha: string;
  try {
    commitSha = execSync(`git -C "${repoPath}" rev-parse HEAD`, {
      encoding: 'utf-8',
    }).trim();
  } catch {
    commitSha = 'unknown';
  }

  // Create or use session
  const session =
    input.session ||
    (await Session.create({
      targets: [repoUrl || repoPath],
      name: generateRandomName(),
      config: {
        sessionType: 'static',
        staticConfig: {
          repoUrl,
          repoPath,
          ref,
          fastMode: sessionConfig?.fastMode,
          skipTools: sessionConfig?.skipTools,
        },
      },
    }));

  // Create workspace
  const { runId, paths } = await createWorkspace(session.rootPath);

  // Helper to log to JSONL
  async function appendResultLog(type: string, data: any) {
    await appendToResultsJsonl(paths, { type, ...data });
  }

  // Initialize state
  const state: StaticAnalysisState = {
    run_id: runId,
    repo: {
      root: repoPath,
      url: repoUrl,
      ref,
      commit: commitSha,
    },
    analysis_runs: [],
    candidates: [],
    findings: [],
    completed_stages: [],
    started_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  await saveState(paths, state);
  await appendResultLog('run_started', {
    runId,
    repoPath,
    repoUrl,
    ref,
    commit: commitSha,
    tools: toolAvailability,
  });

  // Track results
  const agentResults = new Map<StaticAnalysisStage, StaticAgentResult>();
  let currentStageIndex = 0;
  let activeAgents = 0;

  // =========================================================================
  // Agent execution helper
  // =========================================================================
  async function runAgent(
    stage: StaticAnalysisStage,
    runFn: () => Promise<StaticAgentResult>
  ): Promise<StaticAgentResult> {
    if (abortSignal?.aborted) {
      return {
        stage,
        success: false,
        artifacts: [],
        summary: 'Aborted',
        error: 'Operation aborted',
        duration_ms: 0,
      };
    }

    const stageNumber = STAGE_ORDER.indexOf(stage) + 1;
    const agentId = `${stage}-${runId}`;

    // Notify spawn
    onAgentSpawn?.({
      id: agentId,
      name: `${STAGE_NAMES[stage]}`,
      stage,
      stageNumber,
    });

    activeAgents++;
    state.current_stage = stage;
    await saveState(paths, state);

    reportProgress(stage, `Running ${STAGE_NAMES[stage]}...`, {
      currentStage: stageNumber,
      stagesCompleted: state.completed_stages.length,
      activeAgents,
    });

    const stageStartTime = Date.now();

    try {
      // Set up timeout
      const timeoutMs = AGENT_TIMEOUTS[stage];
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(
          () => reject(new Error(`Agent ${stage} timed out after ${timeoutMs}ms`)),
          timeoutMs
        );
      });

      // Run with timeout
      const result = await Promise.race([runFn(), timeoutPromise]);

      // Record success
      state.completed_stages.push(stage);
      state.updated_at = new Date().toISOString();
      await saveState(paths, state);

      await appendResultLog('agent_complete', {
        agent: stage,
        success: result.success,
        duration_ms: result.duration_ms,
        artifacts: result.artifacts,
        summary: result.summary,
      });

      // Notify completion
      onAgentComplete?.(agentId, result);

      return result;
    } catch (error: any) {
      const errorResult: StaticAgentResult = {
        stage,
        success: false,
        artifacts: [],
        summary: `${STAGE_NAMES[stage]} failed: ${error.message}`,
        error: error.message,
        duration_ms: Date.now() - stageStartTime,
      };

      await appendResultLog('agent_error', {
        agent: stage,
        error: error.message,
        duration_ms: errorResult.duration_ms,
      });

      // Notify completion with error
      onAgentComplete?.(agentId, errorResult);

      return errorResult;
    } finally {
      activeAgents--;
    }
  }

  // =========================================================================
  // Step 3: Run pipeline stages
  // =========================================================================

  // Create step finish handler for agents that support it
  const createStepHandler = (stage: StaticAnalysisStage) => (step: any) => {
    const agentId = `${stage}-${runId}`;
    onAgentStream?.({
      type: 'step-finish',
      agentId,
      data: {
        text: step.text,
        toolCalls: step.toolCalls,
        toolResults: step.toolResults,
        usage: step.usage,
      },
    });
  };

  try {
    // Stage 1: RepoIntake
    const intakeResult = await runAgent('repo-intake', () =>
      runRepoIntakeAgent({
        paths,
        state,
        model,
        toolAvailability,
        abortSignal,
        onStepFinish: createStepHandler('repo-intake'),
      })
    );
    agentResults.set('repo-intake', intakeResult);

    if (!intakeResult.success) {
      throw new Error(`RepoIntake failed: ${intakeResult.error}`);
    }

    // Reload state after intake
    const stateAfterIntake = await loadState(paths);
    Object.assign(state, stateAfterIntake);

    // Stage 2: IndexGraph (stub - fast)
    const indexResult = await runAgent('index-graph', () =>
      runIndexGraphAgent({
        paths,
        state,
        model,
        abortSignal,
        onStepFinish: createStepHandler('index-graph'),
      })
    );
    agentResults.set('index-graph', indexResult);

    // Stage 3: Analyzer (runs tools in parallel internally)
    const analyzerResult = await runAgent('analyzer', () =>
      runAnalyzerAgent({
        paths,
        state,
        model,
        toolAvailability,
        abortSignal,
        onProgress: (msg) => {
          reportProgress('analyzer', msg, {
            currentStage: 3,
            stagesCompleted: state.completed_stages.length,
          });
        },
      })
    );
    agentResults.set('analyzer', analyzerResult);

    // Reload state after analyzer
    const stateAfterAnalyzer = await loadState(paths);
    Object.assign(state, stateAfterAnalyzer);

    // Stage 4: SpecSynth (stub)
    const specResult = await runAgent('spec-synth', () =>
      runSpecSynthAgent({
        paths,
        state,
        model,
        abortSignal,
        onStepFinish: createStepHandler('spec-synth'),
      })
    );
    agentResults.set('spec-synth', specResult);

    // Stage 5: VulRAG (stub - waiting for knowledge base)
    const ragResult = await runAgent('vul-rag', () =>
      runVulRAGAgent({
        paths,
        state,
        model,
        abortSignal,
        onStepFinish: createStepHandler('vul-rag'),
      })
    );
    agentResults.set('vul-rag', ragResult);

    // Stage 6: Localize
    const localizeResult = await runAgent('localize', () =>
      runLocalizeAgent({
        paths,
        state,
        model,
        abortSignal,
        onStepFinish: createStepHandler('localize'),
      })
    );
    agentResults.set('localize', localizeResult);

    // Stage 7: Triage
    const triageResult = await runAgent('triage', () =>
      runTriageAgent({
        paths,
        state,
        model,
        abortSignal,
        onStepFinish: createStepHandler('triage'),
      })
    );
    agentResults.set('triage', triageResult);

    // Reload state after triage
    const stateAfterTriage = await loadState(paths);
    Object.assign(state, stateAfterTriage);

    // Stage 8: Report
    const reportResult = await runAgent('report', () =>
      runReportAgent({
        paths,
        state,
        model,
        reportTitle: `Security Analysis: ${repoUrl || path.basename(repoPath)}`,
      })
    );
    agentResults.set('report', reportResult);

    // Final state reload
    const finalState = await loadState(paths);
    Object.assign(state, finalState);

  } catch (error: any) {
    state.error = error.message;
    state.updated_at = new Date().toISOString();
    await saveState(paths, state);

    await appendResultLog('run_failed', {
      error: error.message,
      completedStages: state.completed_stages,
      duration_ms: Date.now() - startTime,
    });

    throw error;
  }

  // =========================================================================
  // Step 4: Collect findings and generate summary
  // =========================================================================

  // Load all findings
  const findings: StaticFinding[] = [];
  const findingsDir = paths.artifacts.findings;

  try {
    const findingFiles = await fs.readdir(findingsDir);
    for (const file of findingFiles) {
      if (file.endsWith('.json') && file.startsWith('finding-')) {
        const content = await fs.readFile(path.join(findingsDir, file), 'utf-8');
        findings.push(JSON.parse(content));
      }
    }
  } catch {
    // No findings directory or no findings
  }

  // Count findings by status
  const confirmedFindings = findings.filter(
    (f) => f.status === 'confirmed' || f.status === 'triaged'
  );

  // Generate summary
  const summary = generateSummary(state, agentResults, confirmedFindings);

  // Log completion
  const totalDuration = Date.now() - startTime;
  await appendResultLog('run_complete', {
    runId,
    duration_ms: totalDuration,
    totalFindings: confirmedFindings.length,
    completedStages: state.completed_stages,
    reportPaths: state.report,
  });

  reportProgress('complete', summary, {
    stagesCompleted: 8,
    findingsCount: confirmedFindings.length,
    activeAgents: 0,
  });

  return {
    session,
    state,
    findings: confirmedFindings,
    totalFindings: confirmedFindings.length,
    reportPaths: state.report || { sarif: '', md: '', json: '' },
    summary,
    duration_ms: totalDuration,
  };
}

/**
 * Generate a summary of the analysis
 */
function generateSummary(
  state: StaticAnalysisState,
  agentResults: Map<StaticAnalysisStage, StaticAgentResult>,
  findings: StaticFinding[]
): string {
  const lines: string[] = [
    '='.repeat(50),
    'STATIC ANALYSIS SUMMARY',
    '='.repeat(50),
    '',
    `Repository: ${state.repo.url || state.repo.root}`,
    `Commit: ${state.repo.commit}`,
    `Ref: ${state.repo.ref}`,
    '',
    `Total Findings: ${findings.length}`,
  ];

  // Count by severity
  const bySeverity = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  lines.push('');
  lines.push('Findings by Severity:');
  lines.push(`  Critical: ${bySeverity.critical}`);
  lines.push(`  High: ${bySeverity.high}`);
  lines.push(`  Medium: ${bySeverity.medium}`);
  lines.push(`  Low: ${bySeverity.low}`);

  // Analysis tools run
  if (state.analysis_runs.length > 0) {
    lines.push('');
    lines.push('Analysis Tools Run:');
    for (const run of state.analysis_runs) {
      const status = run.success ? 'OK' : 'FAILED';
      lines.push(`  - ${run.tool}: ${status} (${run.raw_findings_count} raw findings)`);
    }
  }

  // Stage status
  lines.push('');
  lines.push('Pipeline Stages:');
  for (const stage of STAGE_ORDER) {
    const result = agentResults.get(stage);
    if (result) {
      const status = result.success ? 'OK' : 'FAILED';
      const duration = Math.round(result.duration_ms / 1000);
      lines.push(`  ${STAGE_NAMES[stage]}: ${status} (${duration}s)`);
    } else {
      lines.push(`  ${STAGE_NAMES[stage]}: SKIPPED`);
    }
  }

  // Report paths
  if (state.report) {
    lines.push('');
    lines.push('Reports Generated:');
    lines.push(`  SARIF: ${state.report.sarif}`);
    lines.push(`  Markdown: ${state.report.md}`);
    lines.push(`  JSON: ${state.report.json}`);
  }

  lines.push('');
  lines.push('='.repeat(50));

  return lines.join('\n');
}

export { STAGE_ORDER, STAGE_NAMES, AGENT_TIMEOUTS };
