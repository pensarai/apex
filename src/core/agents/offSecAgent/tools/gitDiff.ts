import { tool } from "ai";
import { z } from "zod";
import { runGit } from "./gitStatus";
import type { ToolContext } from "./types";

const gitDiffInputSchema = z.object({
  path: z
    .string()
    .optional()
    .describe("Optional path to limit the diff to a single file or directory"),
  staged: z
    .boolean()
    .optional()
    .describe("If true, show staged (--cached) diff. Default: unstaged."),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Review unstaged patch before finalize')",
    ),
});

export type GitDiffResult = {
  success: boolean;
  error: string;
  diff: string;
  cwd: string;
};

const MAX_DIFF = 100_000;

export function gitDiff(ctx: ToolContext) {
  return tool({
    description: `Show the git diff for the agent repository.

Defaults to unstaged working-tree changes. Set staged=true for the index.
Optionally pass path to limit output to one file/directory.
Does not commit, stage, push, or open a PR.`,
    inputSchema: gitDiffInputSchema,
    execute: async ({ path, staged = false }): Promise<GitDiffResult> => {
      const args = ["diff"];
      if (staged) args.push("--cached");
      if (path) args.push("--", path);

      const result = await runGit(ctx, args);
      if (!result.success) {
        return {
          success: false,
          error: result.stderr || "git diff failed",
          diff: result.stdout,
          cwd: ctx.agentCwd,
        };
      }

      const raw = result.stdout;
      const truncated = raw.length > MAX_DIFF;
      return {
        success: true,
        error: truncated
          ? `Diff truncated to ${MAX_DIFF} characters — narrow with path`
          : "",
        diff: truncated
          ? `${raw.slice(0, MAX_DIFF)}\n\n(truncated)`
          : raw || "(no changes)",
        cwd: ctx.agentCwd,
      };
    },
  });
}
