import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import { PATCHING_SYSTEM_PROMPT, buildPatchingPrompt } from "./prompts";
import {
  PatchResultSchema,
  type PatchResult,
  type PatchingAgentInput,
} from "./types";

/**
 * A security patching agent that analyzes vulnerabilities and applies fixes.
 *
 * Operates in "lite mode" — no sandbox, no code execution, no POC verification.
 * Uses filesystem tools to read, search, and modify code directly.
 *
 * Returns a structured {@link PatchResult} with the list of changed files,
 * PR title, and PR description.
 *
 * @example
 * ```ts
 * const agent = new PatchingAgent({
 *   cwd: "/tmp/cloned-repo",
 *   vulnerability: {
 *     name: "SQL Injection in login handler",
 *     severity: "critical",
 *     description: "User input concatenated into SQL query",
 *     location: "src/auth/login.ts",
 *   },
 *   model: "claude-sonnet-4-20250514",
 *   session,
 * });
 *
 * const result = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 * });
 *
 * console.log(result.prTitle);
 * console.log(result.filesChanged);
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
      callbacks,
    } = opts;

    super({
      system: PATCHING_SYSTEM_PROMPT,
      prompt: buildPatchingPrompt(vulnerability, cwd),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      callbacks,

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
