import type { OffensiveSecurityAgentInput } from "../agents/offSecAgent";

import { OffensiveSecurityAgent } from "../agents/offSecAgent/offensiveSecurityAgent";
export async function runOffensiveSecurityAgent(
  input: OffensiveSecurityAgentInput,
) {
  const agent = new OffensiveSecurityAgent(input);
  return agent.consume();
}
