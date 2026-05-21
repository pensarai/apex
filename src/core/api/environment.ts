import { EnvironmentAgent } from "../agents/specialized/environment/agent";
import type {
  EnvironmentAgentInput,
  EnvironmentResult,
} from "../agents/specialized/environment/types";

export type { EnvironmentAgentInput, EnvironmentResult };

function attachDefaultEnvironmentStreamListeners(
  agent: EnvironmentAgent,
): void {
  agent.eventBus.on("text-delta", (e) => {
    process.stdout.write(e.text);
  });
  agent.eventBus.on("tool-call-complete", (e) => {
    process.stdout.write(`→ calling ${e.toolName}\n`);
  });
  agent.eventBus.on("tool-result", (e) => {
    process.stdout.write(`✓ ${e.toolName} completed\n`);
  });
  agent.eventBus.on("error", (e) => {
    process.stderr.write(`Environment agent error: ${e.error}\n`);
  });
}

/**
 * Run the environment agent to set up a development environment in a sandbox.
 *
 * The agent reads project files, starts services, and validates the
 * environment is healthy. When a sandbox is provided in the input,
 * tools automatically route operations through it.
 *
 * When no `eventBus` is passed on the input, default stdout / console
 * listeners are attached to the agent's bus for local CLI use.
 *
 * @returns Structured result with application URL, status, steps taken,
 *          and authentication details.
 */
export async function runEnvironmentAgent(
  input: EnvironmentAgentInput,
): Promise<EnvironmentResult> {
  const agent = new EnvironmentAgent(input);
  if (!input.eventBus) {
    attachDefaultEnvironmentStreamListeners(agent);
  }
  return agent.consume();
}
