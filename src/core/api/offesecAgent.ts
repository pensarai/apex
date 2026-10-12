import type { StreamTextResult, ToolSet } from "ai";
import {
  type CreateAgentInput,
  OffensiveSecurityAgent,
  type OffensiveSecurityAgentInput,
} from "../agents/offSecAgent";
import { startAgentExecution } from "../runtime/agentExecution";
import type { SessionInfo } from "../session";

export interface RunAgentResult {
  streamResult: StreamTextResult<ToolSet, never>;
  session: SessionInfo;
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
  const agent = input.session
    ? new OffensiveSecurityAgent(input as OffensiveSecurityAgentInput)
    : await OffensiveSecurityAgent.create(input as CreateAgentInput);

  input.onSessionReady?.(agent.session);

  await startAgentExecution(agent).result;
  return { streamResult: agent.streamResult, session: agent.session };
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
  run: (input: OffensiveSecurityAgentClientInput) => Promise<RunAgentResult>;
  abort: () => void;
} {
  const controller = new AbortController();
  let started = false;
  return {
    run(input) {
      if (started) {
        throw new Error(
          "Offensive security agent client already started a run — create a new client per run",
        );
      }
      started = true;
      return runOffensiveSecurityAgent({
        ...input,
        abortSignal: controller.signal,
      });
    },
    abort() {
      controller.abort();
    },
  };
}
