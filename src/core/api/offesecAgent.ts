import type {
  OffensiveSecurityAgentInput,
  CreateAgentInput,
} from "../agents/offSecAgent";
import type { StreamTextResult, ToolSet } from "ai";

import { OffensiveSecurityAgent } from "../agents/offSecAgent/offensiveSecurityAgent";

/**
 * Run the offensive security agent, consuming its stream to completion.
 *
 * Accepts either a full {@link OffensiveSecurityAgentInput} (with a
 * pre-existing session) or a {@link CreateAgentInput} where `session`
 * is optional and will be auto-created.
 */
export async function runOffensiveSecurityAgent(
  input: OffensiveSecurityAgentInput | CreateAgentInput,
): Promise<StreamTextResult<ToolSet, never>> {
  const agent = input.session
    ? new OffensiveSecurityAgent(input as OffensiveSecurityAgentInput)
    : await OffensiveSecurityAgent.create(input as CreateAgentInput);

  await agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
    subagentCallbacks: input.callbacks?.subagentCallbacks,
  });
  return agent.streamResult;
}
