import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

const gitStatusInputSchema = z.object({
  toolCallDescription: z
    .string()
    .optional()
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

async function runGit(
  ctx: ToolContext,
  args: string[],
): Promise<{ success: boolean; stdout: string; stderr: string }> {
  const command = `git ${args.map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(" ")}`;
  const full = `cd "${ctx.agentCwd}" && ${command}`;

  if (ctx.sandbox) {
    const result = await ctx.sandbox.execute(full, { timeout: 30 });
    return {
      success: result.success,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }

  if (ctx.persistentShell) {
    const result = await ctx.persistentShell.execute(
      full,
      30,
      undefined,
      ctx.abortSignal,
    );
    return {
      success: result.exitCode === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }

  return {
    success: false,
    stdout: "",
    stderr: "No shell or sandbox available",
  };
}

export function gitStatus(ctx: ToolContext) {
  return tool({
    description: `Show git working-tree status (porcelain) for the agent repository.

Use this to self-check which files you changed before finalizing.
Does not commit, stage, push, or open a PR.`,
    inputSchema: gitStatusInputSchema,
    execute: async (): Promise<GitStatusResult> => {
      const result = await runGit(ctx, ["status", "--porcelain"]);
      if (!result.success) {
        return {
          success: false,
          error: result.stderr || "git status failed",
          status: result.stdout,
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

// Re-export helper for git_diff tool
export { runGit };
