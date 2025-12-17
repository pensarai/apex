/**
 * PentestAgent Orchestrator
 *
 * This is the refactored PentestAgent that orchestrates vulnerability testing
 * by spawning VulnerabilityTestAgents in parallel across all targets.
 *
 * All (target, vulnerabilityClass) pairs are dispatched in parallel with
 * a configurable concurrency limit (default: 20).
 */

import type { AIModel } from '../../ai';
import type { PentestTarget } from '../attackSurfaceAgent/types';
import {
  inferVulnerabilityClasses,
  getVulnerabilityClassName,
} from './prompts';
import {
  runMetaVulnerabilityTestAgent,
  type MetaVulnerabilityTestResult,
} from '../metaTestingAgent';
import { Session } from '../../session';
import { Logger } from '../logger';
import { join } from 'path';
import { mkdirSync, existsSync, writeFileSync } from 'fs';
import pLimit from 'p-limit';
import type {
  ExecuteCommandOpts,
  ExecuteCommandResult,
  HttpRequestOpts,
  HttpRequestResult,
} from '../tools';
import type { VulnerabilityClass } from './types';
import { generateRandomName } from '../../../util/name';

/**
 * Save orchestrator summary to the subagents directory
 */
function saveOrchestratorSummary(
  sessionRootPath: string,
  summary: {
    targets: PentestTarget[];
    testTasks: Array<{ target: string; vulnClass: VulnerabilityClass }>;
    results: Array<{ target: string; vulnClass: VulnerabilityClass; findingsCount: number; success: boolean }>;
    totalFindings: number;
    concurrencyLimit: number;
  }
): string {
  const subagentsDir = join(sessionRootPath, 'subagents');
  if (!existsSync(subagentsDir)) {
    mkdirSync(subagentsDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `orchestrator-summary-${timestamp}.json`;
  const filepath = join(subagentsDir, filename);

  const data = {
    agentName: 'pentest-orchestrator',
    timestamp: new Date().toISOString(),
    ...summary,
  };

  writeFileSync(filepath, JSON.stringify(data, null, 2));
  return filepath;
}

/** Default concurrency limit for parallel agent execution */
const DEFAULT_CONCURRENCY_LIMIT = 20;

/**
 * Info about a spawned sub-agent
 */
export interface SubAgentSpawnInfo {
  id: string;
  name: string;
  target: string;
  vulnerabilityClass: VulnerabilityClass;
}

/**
 * Stream event from a sub-agent
 */
export interface SubAgentStreamEvent {
  type: 'text-delta' | 'tool-call' | 'tool-result' | 'step-finish';
  agentId: string;
  data: any;
}

/**
 * Input for the pentest orchestrator
 */
export interface PentestOrchestratorInput {
  /** Targets from AttackSurfaceAgent */
  targets: PentestTarget[];

  /** AI model to use */
  model: AIModel;

  /** Optional existing session */
  session?: Session.SessionInfo;

  /** Session configuration */
  sessionConfig?: {
    outcomeGuidance?: string;
    scopeConstraints?: any;
    authenticationInstructions?: string;
    remoteSandboxUrl?: string;
  };

  /** Progress callback */
  onProgress?: (status: PentestProgressStatus) => void;

  /** Callback when a sub-agent is spawned */
  onAgentSpawn?: (info: SubAgentSpawnInfo) => void;

  /** Callback for stream events from sub-agents */
  onAgentStream?: (event: SubAgentStreamEvent) => void;

  /** Callback when a sub-agent completes */
  onAgentComplete?: (agentId: string, result: MetaVulnerabilityTestResult) => void;

  /** Abort signal */
  abortSignal?: AbortSignal;

  /** Tool overrides for sandboxed execution */
  toolOverride?: {
    execute_command?: (opts: ExecuteCommandOpts) => Promise<ExecuteCommandResult>;
    http_request?: (opts: HttpRequestOpts) => Promise<HttpRequestResult>;
  };

  /** Maximum number of concurrent agents (default: 20) */
  concurrencyLimit?: number;
}

/**
 * Progress status reported during orchestration
 */
export interface PentestProgressStatus {
  phase: 'starting' | 'testing' | 'reporting' | 'complete';
  currentTarget?: string;
  currentVulnClass?: VulnerabilityClass;
  targetsCompleted: number;
  totalTargets: number;
  tasksCompleted: number;
  totalTasks: number;
  activeAgents: number;
  findingsCount: number;
  message: string;
}

/**
 * Result from testing a single target
 */
export interface TargetTestResult {
  target: string;
  objective: string;
  vulnerabilityResults: Map<VulnerabilityClass, MetaVulnerabilityTestResult>;
  totalFindings: number;
  startTime: string;
  endTime: string;
}

/**
 * Overall orchestrator result
 */
export interface PentestOrchestratorResult {
  session: Session.SessionInfo;
  targetResults: TargetTestResult[];
  totalTargets: number;
  totalFindings: number;
  summary: string;
}

/**
 * Represents a single test task (target + vulnerability class pair)
 */
interface TestTask {
  targetIndex: number;
  target: string;
  objective: string;
  authenticationInfo?: any;
  vulnClass: VulnerabilityClass;
}

/**
 * Run the pentest orchestrator
 *
 * Dispatches all (target, vulnerabilityClass) pairs in parallel with
 * a configurable concurrency limit (default: 20).
 */
export async function runPentestOrchestrator(
  input: PentestOrchestratorInput
): Promise<PentestOrchestratorResult> {
  const {
    targets,
    model,
    sessionConfig,
    onProgress,
    onAgentSpawn,
    onAgentStream,
    onAgentComplete,
    abortSignal,
    toolOverride,
    concurrencyLimit = DEFAULT_CONCURRENCY_LIMIT,
  } = input;

  // Create or use session
  const session = input.session || await Session.create({
    targets: targets.map(t => t.target),
    ...sessionConfig,
    name: generateRandomName()
  });

  const logger = new Logger(session, 'orchestrator.log');
  const outcomeGuidance = session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE;

  // Ensure directories exist
  const pocsPath = join(session.rootPath, 'pocs');
  if (!existsSync(pocsPath)) {
    mkdirSync(pocsPath, { recursive: true });
  }

  // Build all test tasks: flatten (target, vulnClass) pairs
  const testTasks: TestTask[] = [];
  for (let i = 0; i < targets.length; i++) {
    const pentestTarget = targets[i];
    const vulnClasses = inferVulnerabilityClasses(pentestTarget.objective);

    for (const vulnClass of vulnClasses) {
      testTasks.push({
        targetIndex: i,
        target: pentestTarget.target,
        objective: pentestTarget.objective,
        authenticationInfo: pentestTarget.authenticationInfo,
        vulnClass,
      });
    }
  }

  logger.info(`Starting pentest orchestrator: ${targets.length} targets, ${testTasks.length} tasks, concurrency limit ${concurrencyLimit}`);

  // Progress tracking
  let tasksCompleted = 0;
  let activeAgents = 0;
  let totalFindings = 0;
  const completedTargets = new Set<number>();

  // Results storage: targetIndex -> vulnClass -> result
  const resultsMap = new Map<number, Map<VulnerabilityClass, MetaVulnerabilityTestResult>>();
  const targetStartTimes = new Map<number, string>();
  const targetEndTimes = new Map<number, string>();

  // Initialize results map for each target
  for (let i = 0; i < targets.length; i++) {
    resultsMap.set(i, new Map());
    targetStartTimes.set(i, new Date().toISOString());
  }

  // Report progress helper
  const reportProgress = (status: Partial<PentestProgressStatus>) => {
    onProgress?.({
      phase: 'testing',
      targetsCompleted: completedTargets.size,
      totalTargets: targets.length,
      tasksCompleted,
      totalTasks: testTasks.length,
      activeAgents,
      findingsCount: totalFindings,
      message: '',
      ...status,
    });
  };

  reportProgress({
    phase: 'starting',
    message: `Starting pentest: ${targets.length} targets, ${testTasks.length} tasks (max ${concurrencyLimit} parallel)`,
  });

  // Create concurrency limiter
  const limit = pLimit(concurrencyLimit);

  // Execute all tasks in parallel with concurrency limit
  const taskPromises = testTasks.map((task) =>
    limit(async () => {
      if (abortSignal?.aborted) {
        return { task, result: null };
      }

      activeAgents++;
      reportProgress({
        currentTarget: task.target,
        currentVulnClass: task.vulnClass,
        message: `Testing ${task.target} for ${getVulnerabilityClassName(task.vulnClass)}`,
      });

      // Generate unique agent ID for this task
      const agentId = `meta-vuln-${task.targetIndex}-${task.vulnClass}`;

      // Notify spawn
      onAgentSpawn?.({
        id: agentId,
        name: `${getVulnerabilityClassName(task.vulnClass)} on ${task.target}`,
        target: task.target,
        vulnerabilityClass: task.vulnClass,
      });

      try {
        const result = await runMetaVulnerabilityTestAgent({
          input: {
            target: task.target,
            objective: task.objective,
            vulnerabilityClass: task.vulnClass,
            authenticationInfo: task.authenticationInfo,
            authenticationInstructions: session.config?.authenticationInstructions,
            outcomeGuidance,
            session: {
              id: session.id,
              rootPath: session.rootPath,
              findingsPath: session.findingsPath,
              logsPath: session.logsPath,
              pocsPath,
            },
          },
          model,
          remoteSandboxUrl: sessionConfig?.remoteSandboxUrl,
          toolOverride,
          abortSignal,
          onStream: (chunk) => {
            // Forward text-delta chunks for real-time streaming
            if (chunk.type === 'text-delta') {
              onAgentStream?.({
                type: 'text-delta',
                agentId,
                data: {
                  textDelta: chunk.textDelta,
                },
              });
            }
          },
          onStepFinish: (step) => {
            // Forward step events to caller
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
          },
        });

        // Notify completion
        onAgentComplete?.(agentId, result);

        return { task, result };
      } catch (error: any) {
        logger.error(`Error testing ${task.vulnClass} on ${task.target}: ${error.message}`);
        return {
          task,
          result: {
            vulnerabilitiesFound: false,
            findingsCount: 0,
            pocPaths: [],
            findingPaths: [],
            summary: `Error: ${error.message}`,
            error: error.message,
          } as MetaVulnerabilityTestResult,
        };
      } finally {
        activeAgents--;
        tasksCompleted++;

        // Update target end time
        targetEndTimes.set(task.targetIndex, new Date().toISOString());

        reportProgress({
          message: `Completed ${tasksCompleted}/${testTasks.length} tasks`,
        });
      }
    })
  );

  // Wait for all tasks to complete
  const taskResults = await Promise.all(taskPromises);

  // Aggregate results by target
  for (const { task, result } of taskResults) {
    if (result) {
      const targetResults = resultsMap.get(task.targetIndex)!;
      targetResults.set(task.vulnClass, result);
      totalFindings += result.findingsCount;
    }
  }

  // Build final target results
  const targetResults: TargetTestResult[] = [];
  for (let i = 0; i < targets.length; i++) {
    const pentestTarget = targets[i];
    const vulnerabilityResults = resultsMap.get(i)!;
    const targetFindingsCount = Array.from(vulnerabilityResults.values())
      .reduce((sum, r) => sum + r.findingsCount, 0);

    targetResults.push({
      target: pentestTarget.target,
      objective: pentestTarget.objective,
      vulnerabilityResults,
      totalFindings: targetFindingsCount,
      startTime: targetStartTimes.get(i)!,
      endTime: targetEndTimes.get(i) || new Date().toISOString(),
    });

    logger.info(`Target ${pentestTarget.target} complete. Findings: ${targetFindingsCount}`);
  }

  // Generate summary
  const summary = generateSummary(targetResults, totalFindings);
  logger.info(summary);

  // Save orchestrator summary
  try {
    const orchestratorResults = taskResults.map(({ task, result }) => ({
      target: task.target,
      vulnClass: task.vulnClass,
      findingsCount: result?.findingsCount || 0,
      success: result ? !result.error : false,
    }));

    const savedPath = saveOrchestratorSummary(session.rootPath, {
      targets,
      testTasks: testTasks.map(t => ({ target: t.target, vulnClass: t.vulnClass })),
      results: orchestratorResults,
      totalFindings,
      concurrencyLimit,
    });
    logger.info(`Orchestrator summary saved to: ${savedPath}`);
  } catch (e: any) {
    logger.error(`Failed to save orchestrator summary: ${e.message}`);
  }

  reportProgress({
    phase: 'complete',
    tasksCompleted: testTasks.length,
    totalTasks: testTasks.length,
    activeAgents: 0,
    message: `Pentest complete. Total findings: ${totalFindings}`,
  });

  return {
    session,
    targetResults,
    totalTargets: targets.length,
    totalFindings,
    summary,
  };
}

/**
 * Generate a summary of pentest results
 */
function generateSummary(
  targetResults: TargetTestResult[],
  totalFindings: number
): string {
  const lines: string[] = [
    '='.repeat(50),
    'PENTEST ORCHESTRATOR SUMMARY',
    '='.repeat(50),
    '',
    `Total Targets Tested: ${targetResults.length}`,
    `Total Findings: ${totalFindings}`,
    '',
    'Results by Target:',
  ];

  for (const result of targetResults) {
    lines.push(`  - ${result.target}: ${result.totalFindings} findings`);

    for (const [vulnClass, vulnResult] of Array.from(result.vulnerabilityResults.entries())) {
      if (vulnResult.findingsCount > 0) {
        lines.push(`    • ${getVulnerabilityClassName(vulnClass)}: ${vulnResult.findingsCount}`);
      }
    }
  }

  lines.push('');
  lines.push('='.repeat(50));

  return lines.join('\n');
}
