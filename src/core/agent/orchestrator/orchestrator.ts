/**
 * PentestAgent Orchestrator
 *
 * This is the refactored PentestAgent that orchestrates vulnerability testing
 * by spawning VulnerabilityTestAgents in parallel across all targets.
 *
 * All (target, vulnerabilityClass) pairs are dispatched in parallel with
 * a configurable concurrency limit (default: 20).
 */

import { tool, hasToolCall } from "ai";
import { z } from "zod";
import { streamResponse, type AIModel } from "../../ai";
import { type AIAuthConfig } from "../../ai/utils";
import type {
  PentestTarget,
  AttackSurfaceAnalysisResults,
} from "../attackSurfaceAgent/types";
import {
  inferVulnerabilityClasses,
  getVulnerabilityClassName,
} from "./prompts";
import {
  runMetaVulnerabilityTestAgent,
  type MetaVulnerabilityTestResult,
  type SpawnVulnerabilityTestRequest,
} from "../metaTestingAgent";
import { Session } from "../../session";
import { Logger } from "../logger";
import { join } from "path";
import { mkdirSync, existsSync, writeFileSync, readFileSync } from "fs";
import pLimit from "p-limit";
import type {
  ExecuteCommandOpts,
  ExecuteCommandResult,
  HttpRequestOpts,
  HttpRequestResult,
} from "../tools";
import type { OrchestratorInput, OrchestratorResult } from "./types";
import { SpawnSubagentSchema } from "./types";
import type {
  SubAgentManifest,
  SubAgentConfig,
  VulnerabilityClass,
} from "../subagent/types";
import { VulnerabilityClassSchema } from "../subagent/types";
import { generateRandomName } from "../../../util/name";
import { nanoid } from "nanoid";

/**
 * Save orchestrator summary to the subagents directory
 */
function saveOrchestratorSummary(
  sessionRootPath: string,
  summary: {
    targets: PentestTarget[];
    testTasks: Array<{ target: string; vulnClass: VulnerabilityClass }>;
    results: Array<{
      target: string;
      vulnClass: VulnerabilityClass;
      findingsCount: number;
      success: boolean;
    }>;
    totalFindings: number;
    concurrencyLimit: number;
  }
): string {
  const subagentsDir = join(sessionRootPath, "subagents");
  if (!existsSync(subagentsDir)) {
    mkdirSync(subagentsDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `orchestrator-summary-${timestamp}.json`;
  const filepath = join(subagentsDir, filename);

  const data = {
    agentName: "pentest-orchestrator",
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
  type: "text-delta" | "tool-call" | "tool-result" | "step-finish";
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

  /** Auth config for AI provider authentication (e.g., Bedrock credentialProvider) */
  authConfig?: AIAuthConfig;

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
  onAgentComplete?: (
    agentId: string,
    result: MetaVulnerabilityTestResult
  ) => void;

  /** Abort signal */
  abortSignal?: AbortSignal;

  /** Tool overrides for sandboxed execution */
  toolOverride?: {
    execute_command?: (
      opts: ExecuteCommandOpts
    ) => Promise<ExecuteCommandResult>;
    http_request?: (opts: HttpRequestOpts) => Promise<HttpRequestResult>;
  };

  /** Maximum number of concurrent agents (default: 20) */
  concurrencyLimit?: number;
}

/**
 * Progress status reported during orchestration
 */
export interface PentestProgressStatus {
  phase: "starting" | "testing" | "reporting" | "complete";
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
 * Unified interface for both initial and dynamically spawned tasks
 */
interface TestTask {
  targetIndex: number;
  target: string;
  objective: string;
  authenticationInfo?: any;
  vulnClass: VulnerabilityClass;
  /** Whether this task was dynamically spawned by another agent */
  isSpawned?: boolean;
  /** Evidence that led to spawning this task (for spawned tasks) */
  spawnEvidence?: string;
  /** Priority for spawned tasks */
  spawnPriority?: "critical" | "high" | "medium";
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
    authConfig,
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
  const session =
    input.session ||
    (await Session.create({
      targets: targets.map((t) => t.target),
      ...sessionConfig,
      name: generateRandomName(),
    }));

  const logger = new Logger(session, "orchestrator.log");
  const outcomeGuidance =
    session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE;

  // Ensure directories exist
  const pocsPath = join(session.rootPath, "pocs");
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

  logger.info(
    `Starting pentest orchestrator: ${targets.length} targets, ${testTasks.length} tasks, concurrency limit ${concurrencyLimit}`
  );

  // Progress tracking
  let tasksCompleted = 0;
  let activeAgents = 0;
  let totalFindings = 0;
  const completedTargets = new Set<number>();

  // Results storage: targetIndex -> vulnClass -> result
  const resultsMap = new Map<
    number,
    Map<VulnerabilityClass, MetaVulnerabilityTestResult>
  >();
  const targetStartTimes = new Map<number, string>();
  const targetEndTimes = new Map<number, string>();

  // Initialize results map for each target
  for (let i = 0; i < targets.length; i++) {
    resultsMap.set(i, new Map());
    targetStartTimes.set(i, new Date().toISOString());
  }

  // Create concurrency limiter
  const limit = pLimit(concurrencyLimit);

  // Unified task results array - both initial and spawned tasks get added here
  const allTaskResults: Array<{
    task: TestTask;
    result: MetaVulnerabilityTestResult | null;
  }> = [];

  // Unified promise array - both initial and spawned task promises go here
  const allTaskPromises: Array<
    Promise<{ task: TestTask; result: MetaVulnerabilityTestResult | null }>
  > = [];

  // Track total tasks for progress reporting (includes spawned)
  let totalTasksQueued = testTasks.length;

  // Report progress helper
  const reportProgress = (status: Partial<PentestProgressStatus>) => {
    onProgress?.({
      phase: "testing",
      targetsCompleted: completedTargets.size,
      totalTargets: targets.length,
      tasksCompleted,
      totalTasks: totalTasksQueued,
      activeAgents,
      findingsCount: totalFindings,
      message: "",
      ...status,
    });
  };

  /**
   * Queue a task for execution - used for both initial and spawned tasks
   * Tasks are added to the unified queue and processed with p-limit concurrency
   */
  const queueTask = (task: TestTask) => {
    const promise = limit(async () => {
      if (abortSignal?.aborted) {
        return { task, result: null };
      }

      activeAgents++;
      const taskType = task.isSpawned ? "spawned" : "initial";
      reportProgress({
        currentTarget: task.target,
        currentVulnClass: task.vulnClass,
        message: `[${taskType}] Testing ${
          task.target
        } for ${getVulnerabilityClassName(task.vulnClass)}`,
      });

      // Generate unique agent ID for this task
      const agentId = task.isSpawned
        ? `spawned-${task.vulnClass}-${Date.now()}`
        : `meta-vuln-${task.targetIndex}-${task.vulnClass}`;

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
            authenticationInstructions:
              session.config?.authenticationInstructions,
            outcomeGuidance,
            session: {
              id: session.id,
              rootPath: session.rootPath,
              findingsPath: session.findingsPath,
              logsPath: session.logsPath,
              pocsPath,
            },
            sessionConfig: {
              enableCvssScoring: session.config?.enableCvssScoring,
              cvssModel: session.config?.cvssModel,
            },
          },
          model,
          authConfig,
          remoteSandboxUrl: sessionConfig?.remoteSandboxUrl,
          toolOverride,
          abortSignal,
          // Handle spawned vulnerability tests - adds to the same unified queue
          onSpawnAgent: (request: SpawnVulnerabilityTestRequest) => {
            logger.info(
              `Agent ${agentId} spawning new test: ${request.vulnerabilityClass} for ${request.target}`
            );

            // Create a new task and add it to the unified queue
            const spawnedTask: TestTask = {
              target: request.target,
              targetIndex: task.targetIndex,
              objective: request.objective,
              vulnClass: request.vulnerabilityClass as VulnerabilityClass,
              isSpawned: true,
              spawnEvidence: request.evidence,
              spawnPriority: request.priority,
            };

            totalTasksQueued++;
            queueTask(spawnedTask);

            logger.info(
              `Queued spawned task: ${request.vulnerabilityClass} (total queue: ${totalTasksQueued})`
            );
          },
          // Forward real-time stream chunks to caller
          onChunk: (chunk) => {
            onAgentStream?.({
              type: chunk.type as any,
              agentId,
              data: chunk,
            });
          },
          onStepFinish: (step) => {
            // Forward step events to caller
            onAgentStream?.({
              type: "step-finish",
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

        const taskResult = { task, result };
        allTaskResults.push(taskResult);
        return taskResult;
      } catch (error: any) {
        logger.error(
          `Error testing ${task.vulnClass} on ${task.target}: ${error.message}`
        );
        const taskResult = {
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
        allTaskResults.push(taskResult);
        return taskResult;
      } finally {
        activeAgents--;
        tasksCompleted++;

        // Update target end time
        targetEndTimes.set(task.targetIndex, new Date().toISOString());

        reportProgress({
          message: `Completed ${tasksCompleted}/${totalTasksQueued} tasks`,
        });
      }
    });

    allTaskPromises.push(promise);
    return promise;
  };

  reportProgress({
    phase: "starting",
    message: `Starting pentest: ${targets.length} targets, ${testTasks.length} tasks (max ${concurrencyLimit} parallel)`,
  });

  // Queue all initial tasks
  for (const task of testTasks) {
    queueTask(task);
  }

  // Wait for all tasks including dynamically spawned ones
  // Loop until no new tasks are added during execution
  let processedCount = 0;
  while (processedCount < allTaskPromises.length) {
    const currentLength = allTaskPromises.length;
    await Promise.all(allTaskPromises);

    // If new tasks were added during execution, continue waiting
    if (allTaskPromises.length === currentLength) {
      break;
    }
    processedCount = currentLength;
  }

  logger.info(
    `All tasks completed: ${allTaskResults.length} total (${
      testTasks.length
    } initial + ${allTaskResults.length - testTasks.length} spawned)`
  );

  // Aggregate results by target (includes both initial and spawned tasks)
  for (const { task, result } of allTaskResults) {
    if (result) {
      const targetResultsMap = resultsMap.get(task.targetIndex);
      if (targetResultsMap) {
        // For spawned tasks, we may have multiple results per vuln class
        // Store the most recent or merge findings
        targetResultsMap.set(task.vulnClass, result);
        totalFindings += result.findingsCount;
      }
    }
  }

  // Build final target results
  const targetResults: TargetTestResult[] = [];
  for (let i = 0; i < targets.length; i++) {
    const pentestTarget = targets[i];
    const vulnerabilityResults = resultsMap.get(i)!;
    const targetFindingsCount = Array.from(
      vulnerabilityResults.values()
    ).reduce((sum, r) => sum + r.findingsCount, 0);

    targetResults.push({
      target: pentestTarget.target,
      objective: pentestTarget.objective,
      vulnerabilityResults,
      totalFindings: targetFindingsCount,
      startTime: targetStartTimes.get(i)!,
      endTime: targetEndTimes.get(i) || new Date().toISOString(),
    });

    logger.info(
      `Target ${pentestTarget.target} complete. Findings: ${targetFindingsCount}`
    );
  }

  // Generate summary
  const summary = generateSummary(targetResults, totalFindings);
  logger.info(summary);

  // Save orchestrator summary
  try {
    const orchestratorResults = allTaskResults.map(({ task, result }) => ({
      target: task.target,
      vulnClass: task.vulnClass,
      findingsCount: result?.findingsCount || 0,
      success: result ? !result.error : false,
      isSpawned: task.isSpawned || false,
    }));

    const savedPath = saveOrchestratorSummary(session.rootPath, {
      targets,
      testTasks: allTaskResults.map(({ task }) => ({
        target: task.target,
        vulnClass: task.vulnClass,
        isSpawned: task.isSpawned || false,
      })),
      results: orchestratorResults,
      totalFindings,
      concurrencyLimit,
    });
    logger.info(`Orchestrator summary saved to: ${savedPath}`);
  } catch (e: any) {
    logger.error(`Failed to save orchestrator summary: ${e.message}`);
  }

  const spawnedCount = allTaskResults.filter((r) => r.task.isSpawned).length;
  reportProgress({
    phase: "complete",
    tasksCompleted: allTaskResults.length,
    totalTasks: allTaskResults.length,
    activeAgents: 0,
    message: `Pentest complete. ${allTaskResults.length} tasks (${testTasks.length} initial + ${spawnedCount} spawned). Total findings: ${totalFindings}`,
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
    "=".repeat(50),
    "PENTEST ORCHESTRATOR SUMMARY",
    "=".repeat(50),
    "",
    `Total Targets Tested: ${targetResults.length}`,
    `Total Findings: ${totalFindings}`,
    "",
    "Results by Target:",
  ];

  for (const result of targetResults) {
    lines.push(`  - ${result.target}: ${result.totalFindings} findings`);

    for (const [vulnClass, vulnResult] of Array.from(
      result.vulnerabilityResults.entries()
    )) {
      if (vulnResult.findingsCount > 0) {
        lines.push(
          `    • ${getVulnerabilityClassName(vulnClass)}: ${
            vulnResult.findingsCount
          }`
        );
      }
    }
  }

  lines.push("");
  lines.push("=".repeat(50));

  return lines.join("\n");
}

// =============================================================================
// Original AI-based Orchestrator (used by pipeline.ts)
// =============================================================================

const ORCHESTRATOR_SYSTEM_PROMPT = `You are a security testing orchestrator. Your job is to analyze the attack surface and intelligently spawn sub-agents to test for vulnerabilities.

## Your Role

1. Read and analyze the attack surface JSON (if available)
2. Understand each endpoint's purpose, parameters, and potential vulnerabilities
3. Decide which sub-agents to spawn for each endpoint
4. Consider which vulnerability classes are most relevant based on:
   - Endpoint functionality (auth endpoints → authentication bypass, sqli)
   - Parameter types (file paths → lfi, URLs → ssrf)
   - Technology stack (identified frameworks, databases)
   - Objective hints from attack surface analysis

## Vulnerability Classes

Available vulnerability classes to test:
- sql_injection: SQL/NoSQL injection
- xss: Cross-site scripting
- command_injection: OS command injection
- ssti: Server-side template injection
- path_traversal: LFI/path traversal
- ssrf: Server-side request forgery
- idor: Insecure direct object references
- authentication_bypass: Auth/session vulnerabilities
- jwt_vulnerabilities: JWT attacks
- deserialization: Insecure deserialization
- xxe: XML external entity
- crypto: Cryptographic weaknesses
- business_logic: Logic flaws
- generic: Other vulnerabilities

## Sub-agent Strategy

For each endpoint, consider spawning multiple sub-agents with different vulnerability focuses. For example:
- Login endpoint → authentication_bypass, sql_injection
- File download → path_traversal, idor
- User profile → idor, xss

Prioritize based on:
- critical: RCE potential (command_injection, ssti, deserialization)
- high: Data access (sql_injection, idor, path_traversal)
- medium: XSS, SSRF, crypto
- low: Info disclosure, generic

## Process

1. Call read_attack_surface to load the attack surface data (if available)
2. Optionally use search_source_code (if whitebox mode) to understand handlers
3. Build your sub-agent manifest by calling spawn_subagent for each test
4. Call finalize_manifest when done

Be thorough but intelligent - spawn sub-agents for likely vulnerabilities based on context.`;

const WHITEBOX_SYSTEM_PROMPT = `You are a security testing orchestrator with SOURCE CODE ACCESS. Your job is to analyze the source code for a target endpoint and spawn sub-agents to test for vulnerabilities.

## Your Role (Whitebox Mode)

You have access to the application's source code. Use this to make INFORMED decisions about which vulnerabilities to test. Don't just guess - ANALYZE the code.

## Analysis Process

1. **Find the route handler**: Use search_source_code or list_files to locate the endpoint's route definition
   - Search for the endpoint path in route files
   - Common patterns: \`.get('/path'\`, \`@app.route('/path')\`, \`@GetMapping\`

2. **Analyze the handler code**: Read the handler file to understand:
   - What parameters does it accept?
   - How are parameters used?
   - What database queries are made?
   - What external calls are made?
   - What file operations occur?

3. **Identify vulnerability patterns**: Look for specific code patterns:
   - SQL: String concatenation in queries, raw SQL, ORM misuse
   - Command injection: exec(), spawn(), system(), shell commands
   - Path traversal: File operations with user input, path.join without validation
   - SSTI: Template rendering with user input
   - SSRF: HTTP requests with user-controlled URLs
   - Deserialization: pickle.loads, JSON.parse of untrusted data, unserialize
   - XSS: User input reflected without encoding
   - Auth bypass: Weak session handling, JWT without verification

4. **Spawn targeted sub-agents**: Only spawn sub-agents for vulnerabilities you have evidence for:
   - Found a raw SQL query? → sql_injection
   - Found exec() with user input? → command_injection
   - Found file read with path parameter? → path_traversal

## Available Tools

- list_files: Find files matching a glob pattern (e.g., "**/*routes*.ts", "**/*controller*.py")
- search_source_code: Search for code patterns using regex
- read_file: Read a specific file's contents
- spawn_subagent: Add a sub-agent for a specific vulnerability test
- finalize_manifest: Complete the orchestration

## Vulnerability Classes

- sql_injection: SQL/NoSQL injection - look for query(), execute(), raw SQL strings
- xss: Cross-site scripting - look for innerHTML, dangerouslySetInnerHTML, unescaped output
- command_injection: OS command injection - look for exec, spawn, system, shell commands
- ssti: Server-side template injection - look for render_template with user input
- path_traversal: LFI/path traversal - look for file operations with user-controlled paths
- ssrf: Server-side request forgery - look for HTTP clients with user-controlled URLs
- idor: Insecure direct object references - look for ID parameters without auth checks
- authentication_bypass: Auth vulnerabilities - look for weak auth logic, session handling
- jwt_vulnerabilities: JWT attacks - look for jwt.decode without verify, weak algorithms
- deserialization: Insecure deserialization - look for pickle, yaml.load, unserialize
- xxe: XML external entity - look for XML parsers without entity restrictions
- crypto: Cryptographic weaknesses - look for MD5, SHA1, weak random, hardcoded keys
- business_logic: Logic flaws - look for race conditions, pricing bugs, privilege issues
- nosql_injection: NoSQL injection - look for MongoDB queries with user input
- generic: Other vulnerabilities

## Important Guidelines

- BE SELECTIVE: Only spawn sub-agents for vulnerabilities you found evidence of in the code
- PROVIDE CONTEXT: Include the file path and relevant code snippets in the context field
- PRIORITIZE: Focus on the most critical vulnerabilities first
- DON'T GUESS: If you don't find evidence of a vulnerability pattern, don't spawn a sub-agent for it

## Process

1. Use list_files to find route/controller files
2. Use search_source_code to find the target endpoint's handler
3. Use read_file to examine the handler code in detail
4. Identify specific vulnerability patterns in the code
5. Spawn sub-agents ONLY for vulnerabilities you found evidence of
6. Call finalize_manifest when done`;

function createOrchestratorTools(
  input: OrchestratorInput,
  subagents: SubAgentConfig[]
) {
  const { attackSurfacePath, session, whiteboxMode, sourceCodePath } = input;

  const read_attack_surface = tool({
    description: "Read the attack surface JSON file",
    inputSchema: z.object({}),
    execute: async () => {
      if (!attackSurfacePath) {
        return { success: false, error: "No attack surface file available" };
      }
      try {
        const content = readFileSync(attackSurfacePath, "utf-8");
        const data = JSON.parse(content) as AttackSurfaceAnalysisResults;
        return { success: true, data };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const read_file = tool({
    description:
      "Read a file from the filesystem. Use this to examine source code files in detail.",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content: content.slice(0, 15000) };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const list_files = tool({
    description:
      "List files matching a glob pattern. Use this to find route files, controllers, handlers, etc.",
    inputSchema: z.object({
      pattern: z
        .string()
        .describe(
          "Glob pattern to match files (e.g., '**/*routes*.ts', '**/controllers/**/*.py')"
        ),
    }),
    execute: async ({ pattern }) => {
      if (!whiteboxMode) {
        return {
          success: false,
          error: "File listing only available in whitebox mode",
        };
      }
      const searchPath = sourceCodePath || ".";
      try {
        // Use find with glob pattern via bash
        const proc = Bun.spawn(
          [
            "bash",
            "-c",
            `find "${searchPath}" -type f -name "${pattern
              .replace(/\*\*\//g, "")
              .replace(/\*\*/g, "*")}" 2>/dev/null | head -50`,
          ],
          { stdout: "pipe", stderr: "pipe" }
        );
        const stdout = await new Response(proc.stdout).text();
        const files = stdout.split("\n").filter((f) => f.trim());

        // If the simple find doesn't work well, try fd if available
        if (files.length === 0) {
          const fdProc = Bun.spawn(
            ["fd", "--type", "f", "--glob", pattern, searchPath],
            { stdout: "pipe", stderr: "pipe" }
          );
          const fdStdout = await new Response(fdProc.stdout).text();
          const fdFiles = fdStdout
            .split("\n")
            .filter((f) => f.trim())
            .slice(0, 50);
          return { success: true, files: fdFiles };
        }

        return { success: true, files };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_source_code = tool({
    description:
      "Search source code for patterns using regex. Use this to find route definitions, SQL queries, dangerous functions, etc.",
    inputSchema: z.object({
      pattern: z
        .string()
        .describe(
          "Regex pattern to search (e.g., '\\.get\\s*\\(' for Express routes, 'query\\s*\\(' for SQL)"
        ),
      filePattern: z
        .string()
        .optional()
        .describe("File glob pattern to filter (e.g., '*.ts', '*.py')"),
    }),
    execute: async ({ pattern, filePattern }) => {
      if (!whiteboxMode) {
        return {
          success: false,
          error: "Source code search only available in whitebox mode",
        };
      }
      const searchPath = sourceCodePath || ".";
      try {
        const args = ["--json", "-i", pattern];
        if (filePattern) {
          args.push("-g", filePattern);
        }
        args.push(searchPath);

        const proc = Bun.spawn(["rg", ...args], {
          stdout: "pipe",
          stderr: "pipe",
        });
        const stdout = await new Response(proc.stdout).text();
        const matches = stdout
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((m) => m?.type === "match")
          .slice(0, 50);

        // Format matches for easier reading
        const formattedMatches = matches.map((m: any) => ({
          file: m.data?.path?.text,
          line: m.data?.line_number,
          content: m.data?.lines?.text?.trim(),
        }));

        return {
          success: true,
          matches: formattedMatches,
          count: formattedMatches.length,
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const spawn_subagent = tool({
    description: "Add a sub-agent to the manifest for spawning",
    inputSchema: SpawnSubagentSchema,
    execute: async ({ endpoint, vulnerabilityClass, context, priority, rationale }) => {
      const validClass = VulnerabilityClassSchema.safeParse(vulnerabilityClass);
      if (!validClass.success) {
        return {
          success: false,
          error: `Invalid vulnerability class: ${vulnerabilityClass}. Use one of: sql_injection, nosql_injection, xss, command_injection, ssti, path_traversal, ssrf, idor, authentication_bypass, jwt_vulnerabilities, deserialization, xxe, crypto, business_logic, generic`,
        };
      }

      const subagentId = `subagent-${nanoid(6)}`;
      const config: SubAgentConfig = {
        id: subagentId,
        endpoint,
        vulnerabilityClass: validClass.data,
        context: { ...context, rationale },
        priority,
        whiteboxMode: whiteboxMode || false,
        sourceCodePath,
      };

      subagents.push(config);

      return {
        success: true,
        subagentId,
        message: `Sub-agent ${subagentId} added: ${vulnerabilityClass} testing for ${endpoint}`,
      };
    },
  });

  const finalize_manifest = tool({
    description:
      "Finalize the sub-agent manifest. Call when done adding all sub-agents.",
    inputSchema: z.object({
      summary: z.string().describe("Summary of the orchestration decisions"),
    }),
    execute: async ({ summary }) => {
      return {
        success: true,
        complete: true,
        totalSubagents: subagents.length,
        summary,
      };
    },
  });

  return {
    read_attack_surface,
    read_file,
    list_files,
    search_source_code,
    spawn_subagent,
    finalize_manifest,
  };
}

export async function runOrchestrator(
  input: OrchestratorInput,
  model: AIModel
): Promise<OrchestratorResult> {
  const {
    session,
    attackSurfacePath,
    whiteboxMode,
    sourceCodePath,
    focusEndpoint,
    abortSignal,
    onStepFinish,
  } = input;

  const orchestratorDir = join(session.rootPath, "orchestrator");
  if (!existsSync(orchestratorDir)) {
    mkdirSync(orchestratorDir, { recursive: true });
  }

  const subagents: SubAgentConfig[] = [];
  const tools = createOrchestratorTools(input, subagents);

  // Use whitebox-specific prompt when in whitebox mode
  const systemPrompt = whiteboxMode
    ? WHITEBOX_SYSTEM_PROMPT
    : ORCHESTRATOR_SYSTEM_PROMPT;

  let userPrompt: string;

  if (whiteboxMode && sourceCodePath) {
    // Whitebox mode with source code - focus on code analysis
    userPrompt = `Analyze the source code and create a sub-agent manifest for security testing.

Source code path: ${sourceCodePath}`;

    if (attackSurfacePath && existsSync(attackSurfacePath)) {
      userPrompt += `\nAttack surface file: ${attackSurfacePath} (optional - use if helpful)`;
    }

    if (focusEndpoint) {
      userPrompt += `

## Target Endpoint
${focusEndpoint}

## Your Task

1. **Find the route handler** for ${focusEndpoint}:
   - Use list_files to find route files (e.g., "*routes*", "*controller*", "*handler*")
   - Use search_source_code to search for the endpoint path pattern

2. **Analyze the handler code**:
   - Use read_file to examine the handler implementation
   - Look for how parameters are processed
   - Identify database queries, file operations, external calls

3. **Identify vulnerability patterns**:
   - Look for string concatenation in queries (SQL injection)
   - Look for exec/spawn/system calls (command injection)
   - Look for file operations with user input (path traversal)
   - Look for template rendering with user input (SSTI)
   - Look for HTTP requests with user URLs (SSRF)
   - Look for weak auth checks (auth bypass)

4. **Spawn targeted sub-agents**:
   - ONLY spawn sub-agents for vulnerabilities you found evidence of
   - Include file paths and code snippets in the context field
   - Set appropriate priority based on severity

5. Call finalize_manifest when done`;
    } else {
      userPrompt += `

## Your Task

Analyze the entire codebase to understand the application structure and identify vulnerability patterns.

1. Use list_files to find key files (routes, controllers, models, services)
2. Use search_source_code to find vulnerability patterns
3. Use read_file to examine suspicious code in detail
4. Spawn sub-agents for each endpoint/vulnerability combination you identify
5. Call finalize_manifest when complete`;
    }
  } else {
    // Blackbox mode or no source code - use attack surface
    userPrompt = `Analyze the attack surface and create a sub-agent manifest for security testing.

Attack surface file: ${attackSurfacePath}`;

    if (whiteboxMode) {
      userPrompt += `\n\nThis is a WHITEBOX test. You have access to source code via search_source_code.
Use it to understand handlers, find SQL queries, identify dangerous functions, etc.`;
    }

    if (focusEndpoint) {
      userPrompt += `\n\nFocus specifically on this endpoint: ${focusEndpoint}
Spawn multiple sub-agents with different vulnerability classes for thorough testing.`;
    } else {
      userPrompt += `\n\nAnalyze ALL endpoints in the attack surface.
Spawn appropriate sub-agents for each endpoint based on its functionality.`;
    }

    userPrompt += `\n\nProcess:
1. Read the attack surface
2. Analyze each endpoint (${
      focusEndpoint ? "focusing on " + focusEndpoint : "all endpoints"
    })
3. Spawn sub-agents using spawn_subagent for each relevant vulnerability test
4. Call finalize_manifest when complete`;
  }

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: systemPrompt,
      model,
      tools,
      stopWhen: hasToolCall("finalize_manifest"),
      abortSignal,
      silent: true,
      onStepFinish,
    });

    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
    }

    const manifest: SubAgentManifest = {
      sessionId: session.id,
      createdAt: new Date().toISOString(),
      attackSurfacePath,
      whiteboxMode: whiteboxMode || false,
      subagents,
    };

    const manifestPath = join(orchestratorDir, "subagent-manifest.json");
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    return {
      success: true,
      manifest,
      manifestPath,
    };
  } catch (error: any) {
    const manifest: SubAgentManifest = {
      sessionId: session.id,
      createdAt: new Date().toISOString(),
      attackSurfacePath,
      whiteboxMode: whiteboxMode || false,
      subagents,
    };

    return {
      success: false,
      manifest,
      manifestPath: "",
      error: error.message,
    };
  }
}
