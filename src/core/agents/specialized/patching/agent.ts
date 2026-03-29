import { readFileSync } from "fs";
import { join } from "path";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import { buildSystemPrompt, buildPatchingPrompt } from "./prompts";
import {
  PatchResultSchema,
  type PatchResult,
  type PatchingAgentInput,
} from "./types";

const AGENTS_MD_FILENAMES = [
  "AGENTS.md",
  "agents.md",
  "CLAUDE.md",
  "claude.md",
];
const MAX_AGENTS_MD_SIZE = 50_000;

/**
 * Try to read an AGENTS.md (or similar) file from the repository root.
 * Returns the file content or undefined if none is found.
 */
function readAgentsMd(cwd: string): string | undefined {
  for (const name of AGENTS_MD_FILENAMES) {
    try {
      const content = readFileSync(join(cwd, name), "utf-8");
      if (content.length > MAX_AGENTS_MD_SIZE) {
        return content.slice(0, MAX_AGENTS_MD_SIZE) + "\n\n(truncated)";
      }
      return content;
    } catch {
      // file doesn't exist, try next
    }
  }
  return undefined;
}

/**
 * A security patching agent that analyzes vulnerabilities and applies fixes.
 *
 * Uses filesystem tools to read, search, and modify code directly, and
 * `execute_command` to run lint, type-check, and test suites for verification.
 *
 * When an optional `sandbox` is provided, tools like `execute_command`,
 * `create_file`, and `update_file` automatically route operations through
 * the sandbox instead of the local filesystem.
 *
 * Automatically reads AGENTS.md (or CLAUDE.md) from the repository root and
 * injects it into the prompt so the agent knows the project's build/test
 * commands and conventions.
 *
 * Returns a structured {@link PatchResult} with the list of changed files,
 * PR title, and PR description.
 *
 * @example
 * ```ts
 * const agent = new PatchingAgent({
 *   cwd: "/tmp/cloned-repo",
 *   vulnerability: { name: "SQL Injection", severity: "critical", description: "..." },
 *   model: "claude-sonnet-4-20250514",
 *   session,
 *   sandbox, // optional — tools route through sandbox when provided
 * });
 *
 * const result = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 * });
 * ```
 */
export class PatchingAgent extends OffensiveSecurityAgent<PatchResult> {
  constructor(opts: PatchingAgentInput) {
    const {
      model,
      cwd,
      vulnerability,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      callbacks,
      sandbox,
    } = opts;

    const agentsMd = readAgentsMd(cwd);

    super({
      system: buildSystemPrompt(),
      prompt: buildPatchingPrompt(vulnerability, cwd, agentsMd),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      callbacks,
      sandbox,

      activeTools: [
        "read_file",
        "list_files",
        "grep",
        "create_file",
        "update_file",
        "execute_command",
        "response",
      ],

      responseSchema: PatchResultSchema,
    });
  }
}
