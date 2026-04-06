import type {
  OffensiveSecurityAgentInput,
  CreateAgentInput,
} from "../agents/offSecAgent";
import type { StreamTextResult, ToolSet } from "ai";
import type { SessionInfo } from "../session";

import { OffensiveSecurityAgent } from "../agents/offSecAgent/offensiveSecurityAgent";
import { AgentRun } from "./agentRun";

export interface RunAgentResult {
  streamResult: StreamTextResult<ToolSet, never>;
  session: SessionInfo;
}

type RunnerInput = (
  | Omit<OffensiveSecurityAgentInput, "eventBus">
  | Omit<CreateAgentInput, "eventBus">
) & { onSessionReady?: (session: SessionInfo) => void };

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
export function runOffensiveSecurityAgent(
  input: RunnerInput,
): AgentRun<RunAgentResult> {
  return new AgentRun(async (eventBus) => {
    const fullInput = { ...input, eventBus };
    const agent = fullInput.session
      ? new OffensiveSecurityAgent(fullInput as OffensiveSecurityAgentInput)
      : await OffensiveSecurityAgent.create(fullInput as CreateAgentInput);

    input.onSessionReady?.(agent.session);

    await agent.consume();
    return { streamResult: agent.streamResult, session: agent.session };
  });
}
