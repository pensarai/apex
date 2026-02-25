import { OffensiveSecurityAgent } from "../agents/offSecAgent/offensiveSecurityAgent";
import type { OffensiveSecurityAgentInput } from "../agents/offSecAgent";
import { AgentRun } from "./agentRun";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type OperatorAgentInput = Omit<OffensiveSecurityAgentInput, "eventBus">;

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

/**
 * Run the operator (offensive-security) agent.
 *
 * Returns an {@link AgentRun} that is both async-iterable (for streaming
 * events) and exposes a `.result` promise that resolves when the agent
 * finishes.
 *
 * The caller never needs to create or manage an {@link AgentEventBus} —
 * `AgentRun` handles it internally.
 */
export function runOperatorAgent(input: OperatorAgentInput): AgentRun<void> {
  return new AgentRun(async (eventBus) => {
    const agent = new OffensiveSecurityAgent({ ...input, eventBus });
    return agent.consume();
  });
}
