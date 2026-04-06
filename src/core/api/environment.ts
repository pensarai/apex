import { EnvironmentAgent } from "../agents/specialized/environment/agent";
import type { EnvironmentAgentInput } from "../agents/specialized/environment/types";
import type { EnvironmentResult } from "../agents/specialized/environment/types";

export type { EnvironmentResult, EnvironmentAgentInput };

/**
 * Run the environment agent to set up a development environment in a sandbox.
 *
 * The agent reads project files, starts services, and validates the
 * environment is healthy. When a sandbox is provided in the input,
 * tools automatically route operations through it.
 *
 * @returns Structured result with application URL, status, steps taken,
 *          and authentication details.
 */
export async function runEnvironmentAgent(
  input: EnvironmentAgentInput,
): Promise<EnvironmentResult> {
  const agent = new EnvironmentAgent(input);
  return agent.consume();
}
