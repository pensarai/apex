import type { StreamTextResult, ToolSet } from "ai";
import {
  type CreateAgentInput,
  OffensiveSecurityAgent,
  type OffensiveSecurityAgentInput,
} from "../agents/offSecAgent";
import { startAgentExecution } from "../runtime/agentExecution";
import {
  type SteerInput,
  type SteerResult,
  TurnSteering,
} from "../runtime/turnSteering";
import type { SessionInfo } from "../session";
import {
  persistRootReasoningOverride,
  resolveRootReasoning,
} from "./reasoning";

export interface RunAgentResult {
  streamResult: StreamTextResult<ToolSet, Record<string, unknown>, never>;
  session: SessionInfo;
  messages?: import("ai").ModelMessage[];
  lance?: import("../agents/lance").LanceMetrics;
}

/**
 * Run the offensive security agent, consuming its stream to completion.
 *
 * Accepts either a full {@link OffensiveSecurityAgentInput} (with a
 * pre-existing session) or a {@link CreateAgentInput} where `session`
 * is optional and will be auto-created.
 *
 * Returns the stream result **and** the session so callers can access a
 * session that was auto-created by the factory.
 */
export async function runOffensiveSecurityAgent(
  input: (OffensiveSecurityAgentInput | CreateAgentInput) & {
    onSessionReady?: (session: SessionInfo) => void;
  },
): Promise<RunAgentResult> {
  if (input.mode !== "default-v2") return executeAgent(input);
  let release!: () => void;
  const completed = new Promise<void>((resolve) => {
    release = resolve;
  });
  const path = input.session?.rootPath;
  const previous = path ? researchRuns.get(path) : undefined;
  if (path) researchRuns.set(path, completed);
  let ownedPath = path;
  try {
    await previous;
    input.abortSignal?.throwIfAborted();
    return await executeAgent({
      ...input,
      onSessionReady: (session) => {
        ownedPath = session.rootPath;
        if (!path) researchRuns.set(session.rootPath, completed);
        input.onSessionReady?.(session);
      },
    });
  } finally {
    release();
    if (ownedPath && researchRuns.get(ownedPath) === completed)
      researchRuns.delete(ownedPath);
  }
}

const researchRuns = new Map<string, Promise<void>>();

async function executeAgent(
  input: (OffensiveSecurityAgentInput | CreateAgentInput) & {
    onSessionReady?: (session: SessionInfo) => void;
  },
): Promise<RunAgentResult> {
  const resolved = resolveRootReasoning(input);
  const persisted = persistRootReasoningOverride(input);
  input = persisted ? { ...resolved, session: await persisted } : resolved;
  const agent = input.session
    ? new OffensiveSecurityAgent(input as OffensiveSecurityAgentInput)
    : await OffensiveSecurityAgent.create(input as CreateAgentInput);

  input.onSessionReady?.(agent.session);

  const execution = startAgentExecution(agent);
  try {
    await execution.result;
  } catch (error) {
    if (input.mode === "default-v2") await execution.abortAndDrain();
    throw error;
  }
  if (input.mode === "default-v2") await execution.drained;
  return {
    streamResult: agent.streamResult,
    session: agent.session,
    ...(input.mode === "default-v2" ? { messages: agent.conversation } : {}),
    ...(agent.lanceRuntime
      ? { lance: agent.lanceRuntime.metrics(input.model) }
      : {}),
  };
}

/** Either agent-input shape, minus the abort signal the client owns. */
export type OffensiveSecurityAgentClientInput = (
  | Omit<OffensiveSecurityAgentInput, "abortSignal">
  | Omit<CreateAgentInput, "abortSignal">
) & {
  abortSignal?: never;
  onSessionReady?: (session: SessionInfo) => void;
};

/**
 * Owns the abort signal for one run, so cancellation is available immediately —
 * including while `run` is still awaiting async session creation. Single-use:
 * a second `run` throws; create a fresh client per run.
 */
export function createOffensiveSecurityAgentClient(): {
  readonly turnId: string;
  run: (input: OffensiveSecurityAgentClientInput) => Promise<RunAgentResult>;
  steer: (input: SteerInput) => Promise<SteerResult>;
  abort: () => Promise<void>;
} {
  const controller = new AbortController();
  const steering = new TurnSteering();
  let started = false;
  let running: Promise<RunAgentResult> | undefined;
  return {
    turnId: steering.turnId,
    steer: (input) => steering.steer(input),
    run(input) {
      if (started) {
        throw new Error(
          "Offensive security agent client already started a run — create a new client per run",
        );
      }
      started = true;
      running = runOffensiveSecurityAgent({
        ...input,
        abortSignal: controller.signal,
        steering: input.mode === "default-v2" ? steering : undefined,
      }).finally(() => steering.close());
      return running;
    },
    async abort() {
      steering.close();
      controller.abort();
      await running?.catch(() => {});
    },
  };
}
