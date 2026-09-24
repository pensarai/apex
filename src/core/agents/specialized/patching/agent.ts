import { readFileSync } from "node:fs";
import { join } from "node:path";
import { OffensiveSecurityAgent } from "../../offSecAgent";
import { buildPatchingPrompt, buildSystemPrompt } from "./prompts";
import {
  type PatchingAgentInput,
  type PatchResult,
  PatchResultSchema,
} from "./types";

const AGENTS_MD_FILENAMES = [
  "AGENTS.md",
  "agents.md",
  "CLAUDE.md",
  "claude.md",
];
const MAX_AGENTS_MD_SIZE = 50_000;

/**
 * Tools available to the autonomous patching agent.
 * Mirrors a Cursor / Claude Code coding loop: explore, research, todo,
 * multi-file edit, git self-check, verify, structured finalize.
 */
export const PATCHING_ACTIVE_TOOLS = [
  "read_file",
  "list_files",
  "glob",
  "grep",
  "profile_codebase",
  "run_code_query",
  "web_search",
  "get_page",
  "create_task",
  "update_task",
  "list_tasks",
  "create_file",
  "update_file",
  "delete_file",
  "apply_patch",
  "git_status",
  "git_diff",
  "execute_command",
  "response",
] as const;

/**
 * Try to read an AGENTS.md (or similar) file from the repository root.
 * Returns the file content or undefined if none is found.
 */
export function readAgentsMd(cwd: string): string | undefined {
  for (const name of AGENTS_MD_FILENAMES) {
    try {
      const content = readFileSync(join(cwd, name), "utf-8");
      if (content.length > MAX_AGENTS_MD_SIZE) {
        return `${content.slice(0, MAX_AGENTS_MD_SIZE)}\n\n(truncated)`;
      }
      return content;
    } catch {
      // file doesn't exist, try next
    }
  }
  return undefined;
}

/**
 * Resolve the project instructions for a patching run.
 *
 * Sandbox runs must not import host-side files: the agent reads the repo's own
 * instructions from the actual runtime via read_file instead.
 */
export function resolvePatchingAgentsMd(
  cwd: string,
  sandboxed: boolean,
): string | undefined {
  return sandboxed ? undefined : readAgentsMd(cwd);
}

/**
 * A security patching agent that analyzes vulnerabilities and applies fixes.
 *
 * Uses filesystem tools to read, search, and modify code directly, and
 * `execute_command` to run lint, type-check, and test suites for verification.
 *
 * When an optional `sandbox` is provided, tools like `execute_command`,
 * `create_file`, and `update_file` automatically route operations through
 * the sandbox instead of the local filesystem, and project instructions are
 * read from the runtime rather than the host.
 *
 * The repository (`cwd`) is the agent's working directory: commands start
 * there and relative file-tool paths resolve against it — not against the
 * session root.
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
    const { cwd, vulnerability, ...base } = opts;

    const agentsMd = resolvePatchingAgentsMd(cwd, Boolean(base.sandbox));

    super({
      ...base,
      system: buildSystemPrompt(),
      activeTools: [...PATCHING_ACTIVE_TOOLS],
      responseSchema: PatchResultSchema,
      prompt: buildPatchingPrompt(vulnerability, cwd, agentsMd, {
        runtimeInstructions: Boolean(base.sandbox),
      }),
      agentCwd: cwd,
    });
  }
}
