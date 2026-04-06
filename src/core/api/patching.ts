import { PatchingAgent } from "../agents/specialized/patching/agent";
import type { PatchingAgentInput } from "../agents/specialized/patching/types";
import type { PatchResult } from "../agents/specialized/patching/types";

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
export async function runPatchingAgent(
  input: PatchingAgentInput,
): Promise<PatchResult> {
  const agent = new PatchingAgent(input);
  return agent.consume();
}
