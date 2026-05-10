import { PatchingAgent } from "../agents/specialized/patching/agent";
import type {
  PatchingAgentInput,
  PatchResult,
} from "../agents/specialized/patching/types";

export type { PatchingAgentInput, PatchResult };

function attachDefaultPatchingStreamListeners(agent: PatchingAgent): void {
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
    console.error("Patching agent error:", e.error);
  });
}

/**
 * Run the patching agent to fix a security vulnerability in a codebase.
 *
 * The agent reads, searches, and modifies code, then verifies the fix via
 * lint, type-check, and tests. When a sandbox is provided in the input,
 * tools automatically route operations through it.
 *
 * When no `eventBus` is passed on the input, default stdout / console
 * listeners are attached to the agent's bus for local CLI use.
 *
 * @returns Structured patch result with file changes and PR metadata.
 */
export async function runPatchingAgent(
  input: PatchingAgentInput,
): Promise<PatchResult> {
  const agent = new PatchingAgent(input);
  if (!input.eventBus) {
    attachDefaultPatchingStreamListeners(agent);
  }
  return agent.consume();
}
