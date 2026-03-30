import { EnvironmentAgent } from "../agents/specialized/environment/agent";
import type { EnvironmentAgentInput } from "../agents/specialized/environment/types";
import type { EnvironmentResult } from "../agents/specialized/environment/types";

export type { EnvironmentResult, EnvironmentAgentInput };

function attachDefaultEnvironmentStreamListeners(
  agent: EnvironmentAgent,
): void {
  agent.eventBus.on("text-delta", (e) => {
    process.stdout.write(e.text);
  });
  agent.eventBus.on("tool-call-complete", (e) => {
    console.log(`→ calling ${e.toolName}`);
  });
  agent.eventBus.on("tool-result", (e) => {
    console.log(`✓ ${e.toolName} completed`);
  });
  agent.eventBus.on("error", (e) => {
    console.error("Environment agent error:", e.error);
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
