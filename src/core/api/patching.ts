import { PatchingAgent } from "../agents/specialized/patching/agent";
import type { PatchingAgentInput } from "../agents/specialized/patching/types";
import type { PatchResult } from "../agents/specialized/patching/types";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";

export type { PatchResult, PatchingAgentInput };

export interface RunPatchingAgentInput extends PatchingAgentInput {
  /** Optional callbacks for stream consumption. Falls back to console logging. */
  consumeCallbacks?: ConsumeCallbacks;
}

/**
 * Run the patching agent to fix a security vulnerability in a codebase.
 *
 * The agent operates in lite mode: it reads/searches/modifies code directly
 * on the filesystem without a sandbox or code execution. It returns a
 * structured result with the list of changed files, PR title, and description.
 *
 * @returns Structured patch result with file changes and PR metadata.
 */
export async function runPatchingAgent(
  input: RunPatchingAgentInput,
): Promise<PatchResult> {
  const { consumeCallbacks, ...agentInput } = input;

  const agent = new PatchingAgent(agentInput);

  const result = await agent.consume(
    consumeCallbacks ?? {
      onTextDelta: (d) => process.stdout.write(d.text),
      onToolCall: (d) => console.log(`→ calling ${d.toolName}`),
      onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
      onError: (e) => console.error("Patching agent error:", e),
    },
  );

  return result;
}
