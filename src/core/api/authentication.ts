import {
  AuthenticationAgent,
  type AuthenticationAgentInput,
  type AuthenticationResult,
} from "../agents/specialized/authenticationAgent/agent";
import { AgentRun } from "./agentRun";

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export function runAuthenticationAgent(
  input: Omit<AuthenticationAgentInput, "eventBus">,
): AgentRun<AuthenticationResult> {
  return new AgentRun(async (eventBus) => {
    const agent = new AuthenticationAgent({ ...input, eventBus });
    return agent.consume();
  });
}
