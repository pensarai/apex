import type { OffensiveSecurityAgentInput } from "../agents/offSecAgent";
import type { StreamTextResult, ToolSet } from "ai";

import { OffensiveSecurityAgent } from "../agents/offSecAgent/offensiveSecurityAgent";

export async function runOffensiveSecurityAgent(
  input: OffensiveSecurityAgentInput,
): Promise<StreamTextResult<ToolSet, never>> {
  const agent = new OffensiveSecurityAgent(input);
  await agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
    subagentCallbacks: input.callbacks?.subagentCallbacks,
  });
  return agent.streamResult;
}
