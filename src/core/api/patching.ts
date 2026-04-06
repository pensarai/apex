import { PatchingAgent } from "../agents/specialized/patching/agent";
import type { PatchingAgentInput } from "../agents/specialized/patching/types";
import type { PatchResult } from "../agents/specialized/patching/types";
import { AgentRun } from "./agentRun";

export type { PatchResult, PatchingAgentInput };

/**
 * Run the patching agent to fix a security vulnerability in a codebase.
 *
 * The agent reads, searches, and modifies code, then verifies the fix via
 * lint, type-check, and tests. When a sandbox is provided in the input,
 * tools automatically route operations through it.
 *
 * @returns Structured patch result with file changes and PR metadata.
 */
export function runPatchingAgent(
  input: Omit<PatchingAgentInput, "eventBus">,
): AgentRun<PatchResult> {
  return new AgentRun(async (eventBus) => {
    const agent = new PatchingAgent({ ...input, eventBus });
    return agent.consume();
  });
}
