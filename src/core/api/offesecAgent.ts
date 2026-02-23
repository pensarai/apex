import type { OffensiveSecurityAgentInput } from "../agents/offSecAgent";

import { OffensiveSecurityAgent } from "../agents/offSecAgent/offensiveSecurityAgent";
export async function runOffensiveSecurityAgent(
  input: OffensiveSecurityAgentInput,
) {
  const agent = new OffensiveSecurityAgent(input);
  return agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
    subagentCallbacks: input.callbacks?.subagentCallbacks,
  });
}
