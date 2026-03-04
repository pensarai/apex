import { EnvironmentAgent } from "../agents/specialized/environment/agent";
import type { EnvironmentAgentInput } from "../agents/specialized/environment/types";
import type { EnvironmentResult } from "../agents/specialized/environment/types";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";

export type { EnvironmentResult, EnvironmentAgentInput };

export interface RunEnvironmentAgentInput extends EnvironmentAgentInput {
  /** Optional callbacks for stream consumption. Falls back to console logging. */
  consumeCallbacks?: ConsumeCallbacks;
}

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
  input: RunEnvironmentAgentInput,
): Promise<EnvironmentResult> {
  const { consumeCallbacks, ...agentInput } = input;

  const agent = new EnvironmentAgent(agentInput);

  const result = await agent.consume(
    consumeCallbacks ?? {
      onTextDelta: (d) => process.stdout.write(d.text),
      onToolCall: (d) => console.log(`→ calling ${d.toolName}`),
      onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
      onError: (e) => console.error("Environment agent error:", e),
    },
  );

  return result;
}
