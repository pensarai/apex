import { join } from "path";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "fs";
import type { AIModel } from "../../ai";
import type { Session } from "../../session";
import type {
  SubAgentConfig,
  SubAgentSession,
  InitAgentResult,
  AttackAgentResult,
  Finding,
  AttackPlan,
  VerificationCriteria,
  FileAccessConfig,
} from "./types";
import { runInitAgent } from "./initAgent";
import { runAttackAgent } from "./attackAgent";
import { nanoid } from "nanoid";
import { injectGuidanceFiles, cleanupGuidanceFiles } from "./guidance";

const DEFAULT_SUBAGENT_TIMEOUT = 20 * 60 * 1000; // 20 minutes

export interface RunSubAgentInput {
  config: SubAgentConfig;
  session: Session.SessionInfo;
  workspace: string;
  model: AIModel;
  abortSignal?: AbortSignal;
  /** Tool override for sandboxing execute_command */
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  };
  /** File access restrictions for read_file/write_file/append_file */
  fileAccessConfig?: FileAccessConfig;
  onInitComplete?: (result: InitAgentResult) => void;
  onAttackComplete?: (result: AttackAgentResult) => void;
  /** Callback for each step completion during agent execution (for streaming UI updates) */
  onStepFinish?: (step: {
    text?: string;
    toolCalls?: Array<{ toolCallId: string; toolName: string; args: unknown }>;
    toolResults?: Array<{
      toolCallId: string;
      toolName: string;
      result: unknown;
    }>;
  }) => void;
  /** Callback for each stream chunk (for real-time tool call display) */
  onChunk?: (chunk: {
    type: "text-delta" | "tool-call" | "tool-result";
    text?: string;
    toolCallId?: string;
    toolName?: string;
    args?: unknown;
    result?: unknown;
  }) => void;
  /** Timeout in ms for entire subagent execution (default: 10 minutes) */
  timeout?: number;
}

export interface RunSubAgentResult {
  subagentId: string;
  initResult: InitAgentResult;
  attackResult: AttackAgentResult;
  findings: Finding[];
  success: boolean;
  /** Error details if the subagent failed */
  error?: {
    phase: "init" | "attack" | "timeout" | "unknown";
    message: string;
    timedOut?: boolean;
  };
}

function createSubAgentSession(
  config: SubAgentConfig,
  session: Session.SessionInfo,
): SubAgentSession {
  const subagentId = config.id || `subagent-${nanoid(6)}`;
  const rootPath = join(session.rootPath, "subagents", subagentId);

  mkdirSync(rootPath, { recursive: true });
  mkdirSync(join(rootPath, "scripts"), { recursive: true });
  mkdirSync(join(rootPath, "findings"), { recursive: true });
  mkdirSync(join(rootPath, "logs"), { recursive: true });

  const guidancePath = join(rootPath, "guidance");
  // Inject guidance files for this vulnerability class
  injectGuidanceFiles(guidancePath, config.vulnerabilityClass);

  return {
    id: subagentId,
    sessionId: session.id,
    config,
    rootPath,
    planPath: join(rootPath, "plan.json"),
    verificationPath: join(rootPath, "verification.json"),
    findingsPath: join(rootPath, "findings"),
    scriptsPath: join(rootPath, "scripts"),
    logsPath: join(rootPath, "logs"),
    guidancePath,
  };
}

export async function runSubAgent(
  input: RunSubAgentInput,
): Promise<RunSubAgentResult> {
  const {
    config,
    session,
    workspace,
    model,
    abortSignal,
    toolOverride,
    fileAccessConfig,
    onInitComplete,
    onAttackComplete,
    onStepFinish,
    onChunk,
    timeout = DEFAULT_SUBAGENT_TIMEOUT,
  } = input;

  const subagentSession = createSubAgentSession(config, session);

  // Create timeout abort controller
  const timeoutController = new AbortController();
  const timeoutId = setTimeout(() => timeoutController.abort(), timeout);

  // Combine parent abort signal with timeout signal
  const combinedSignal = abortSignal
    ? AbortSignal.any([abortSignal, timeoutController.signal])
    : timeoutController.signal;

  try {
    // Run init phase with error handling
    let initResult: InitAgentResult;
    try {
      initResult = await runInitAgent(
        subagentSession,
        session,
        model,
        combinedSignal,
        fileAccessConfig,
        onStepFinish,
        onChunk,
      );
      onInitComplete?.(initResult);
    } catch (initError: any) {
      clearTimeout(timeoutId);
      const timedOut =
        timeoutController.signal.aborted && !abortSignal?.aborted;
      return {
        subagentId: subagentSession.id,
        initResult: {
          success: false,
          plan: {} as AttackPlan,
          verificationCriteria: {} as VerificationCriteria,
          error: timedOut
            ? `Init timed out after ${timeout}ms`
            : initError.message,
        },
        attackResult: {
          success: false,
          findings: [],
          summary: "Init phase failed with exception",
          error: initError.message,
        },
        findings: [],
        success: false,
        error: { phase: "init", message: initError.message, timedOut },
      };
    }

    if (!initResult.success) {
      clearTimeout(timeoutId);
      return {
        subagentId: subagentSession.id,
        initResult,
        attackResult: {
          success: false,
          findings: [],
          summary: "Init phase failed, attack not started",
          error: initResult.error,
        },
        findings: [],
        success: false,
        error: {
          phase: "init",
          message: initResult.error || "Unknown init error",
        },
      };
    }

    // Run attack phase with error handling
    let attackResult: AttackAgentResult;
    try {
      attackResult = await runAttackAgent(
        subagentSession,
        session,
        workspace,
        model,
        combinedSignal,
        toolOverride,
        fileAccessConfig,
        onStepFinish,
        onChunk,
      );
      onAttackComplete?.(attackResult);
    } catch (attackError: any) {
      clearTimeout(timeoutId);
      const timedOut =
        timeoutController.signal.aborted && !abortSignal?.aborted;
      const partialFindings = collectPartialFindings(
        subagentSession.findingsPath,
      );
      return {
        subagentId: subagentSession.id,
        initResult,
        attackResult: {
          success: false,
          findings: partialFindings,
          summary: timedOut
            ? `Attack timed out after ${timeout}ms`
            : `Attack failed: ${attackError.message}`,
          error: attackError.message,
        },
        findings: partialFindings,
        success: false,
        error: { phase: "attack", message: attackError.message, timedOut },
      };
    }

    clearTimeout(timeoutId);
    return {
      subagentId: subagentSession.id,
      initResult,
      attackResult,
      findings: attackResult.findings,
      success: attackResult.success,
    };
  } catch (unexpectedError: any) {
    clearTimeout(timeoutId);
    return {
      subagentId: subagentSession.id,
      initResult: {
        success: false,
        plan: {} as AttackPlan,
        verificationCriteria: {} as VerificationCriteria,
        error: unexpectedError.message,
      },
      attackResult: {
        success: false,
        findings: [],
        summary: `Unexpected error: ${unexpectedError.message}`,
        error: unexpectedError.message,
      },
      findings: [],
      success: false,
      error: { phase: "unknown", message: unexpectedError.message },
    };
  } finally {
    // Clean up guidance files after testing completes
    cleanupGuidanceFiles(subagentSession.guidancePath);
  }
}

// Helper to collect findings even on error
function collectPartialFindings(findingsPath: string): Finding[] {
  const findings: Finding[] = [];
  try {
    if (existsSync(findingsPath)) {
      const files = readdirSync(findingsPath).filter((f) =>
        f.endsWith(".json"),
      );
      for (const file of files) {
        try {
          const finding = JSON.parse(
            readFileSync(join(findingsPath, file), "utf-8"),
          );
          findings.push(finding);
        } catch {}
      }
    }
  } catch {}
  return findings;
}

export async function runSubAgentsParallel(
  inputs: RunSubAgentInput[],
  concurrencyLimit: number = 10,
): Promise<RunSubAgentResult[]> {
  const { default: pLimit } = await import("p-limit");
  const limit = pLimit(concurrencyLimit);

  const promises = inputs.map((input) => limit(() => runSubAgent(input)));
  const settledResults = await Promise.allSettled(promises);

  return settledResults.map((result, index) => {
    if (result.status === "fulfilled") {
      return result.value;
    }
    // Convert rejected promise to error result
    const config = inputs[index].config;
    return {
      subagentId: config.id || `unknown-${index}`,
      initResult: {
        success: false,
        plan: {} as AttackPlan,
        verificationCriteria: {} as VerificationCriteria,
        error: result.reason?.message || "Unknown error",
      },
      attackResult: {
        success: false,
        findings: [],
        summary: `Subagent failed: ${result.reason?.message || "Unknown error"}`,
        error: result.reason?.message || "Unknown error",
      },
      findings: [],
      success: false,
      error: {
        phase: "unknown" as const,
        message: result.reason?.message || "Unknown error",
      },
    };
  });
}

/**
 * Run sub-agents in parallel with a callback for each completion
 */
export async function runSubAgentsParallelWithCallbacks(
  inputs: RunSubAgentInput[],
  concurrencyLimit: number = 10,
  onComplete?: (result: RunSubAgentResult) => void,
): Promise<RunSubAgentResult[]> {
  const { default: pLimit } = await import("p-limit");
  const limit = pLimit(concurrencyLimit);

  const promises = inputs.map((input, index) =>
    limit(async () => {
      const result = await runSubAgent(input);
      onComplete?.(result);
      return { result, index };
    }),
  );

  const settledResults = await Promise.allSettled(promises);
  const results: RunSubAgentResult[] = new Array(inputs.length);

  for (const settled of settledResults) {
    if (settled.status === "fulfilled") {
      results[settled.value.index] = settled.value.result;
    } else {
      // Handle unexpected rejection (shouldn't happen with try-catch in runSubAgent)
      const errorResult: RunSubAgentResult = {
        subagentId: "unknown",
        initResult: {
          success: false,
          plan: {} as AttackPlan,
          verificationCriteria: {} as VerificationCriteria,
          error: settled.reason?.message || "Unknown error",
        },
        attackResult: {
          success: false,
          findings: [],
          summary: `Subagent failed: ${settled.reason?.message}`,
          error: settled.reason?.message || "Unknown error",
        },
        findings: [],
        success: false,
        error: {
          phase: "unknown",
          message: settled.reason?.message || "Unknown error",
        },
      };
      onComplete?.(errorResult);
      const emptyIndex = results.findIndex((r) => r === undefined);
      if (emptyIndex !== -1) results[emptyIndex] = errorResult;
    }
  }

  return results;
}

export * from "./types";
export * from "./repl";
export { runInitAgent } from "./initAgent";
export { runAttackAgent } from "./attackAgent";
export {
  buildVerificationPrompt,
  VERIFICATION_GUIDANCE,
} from "./verificationGuidance";
export type { VerificationGuidance } from "./verificationGuidance";
