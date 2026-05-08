import type { StreamTextResult, ToolSet } from "ai";
import {
  type CreateAgentInput,
  OffensiveSecurityAgent,
  type OffensiveSecurityAgentInput,
} from "../agents/offSecAgent";
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

  await agent.consume();
  return { streamResult: agent.streamResult, session: agent.session };
}
