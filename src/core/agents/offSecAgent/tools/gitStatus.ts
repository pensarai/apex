import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

const gitStatusInputSchema = z.object({
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Check which files were modified')",
    ),
});

export type GitStatusResult = {
  success: boolean;
  error: string;
  status: string;
  cwd: string;
};

export function gitStatus(ctx: ToolContext) {
  return tool({
    description: `Show git working-tree status (porcelain) for the agent repository.

Use this to self-check which files you changed before finalizing.
Does not commit, stage, push, or open a PR.`,
    inputSchema: gitStatusInputSchema,
    execute: async (): Promise<GitStatusResult> => {
      const result = await resolveBackends(ctx).fs.git("status");
      // A capped capture is partial evidence: keep the prefix, label it
      // INCOMPLETE — an empty prefix can still hide entries past the cap,
      // so it must never read as "(clean)".
      const truncNote = result.stdoutTruncated
        ? "git status capture truncated at the byte limit — the porcelain list is INCOMPLETE, not the full status"
        : "";
      if (!result.success) {
        const baseError = result.stderr || "git status failed";
        return {
          success: false,
          error: truncNote ? `${baseError}; ${truncNote}` : baseError,
          status: result.stdout,
          cwd: ctx.agentCwd,
        };
      }
      if (result.stdoutTruncated) {
        return {
          success: true,
          error: truncNote,
          status: `${result.stdout.trim()}\n${truncNote}`,
          cwd: ctx.agentCwd,
        };
      }
      return {
        success: true,
        error: "",
        status: result.stdout.trim() || "(clean)",
        cwd: ctx.agentCwd,
      };
    },
  });
}
