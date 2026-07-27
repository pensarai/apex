import { unlink } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

const deleteFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path to the file to delete"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Remove obsolete insecure helper')",
    ),
});

export type DeleteFileResult = {
  success: boolean;
  error: string;
  path: string;
};

function resolveUnderCwd(agentCwd: string, filePath: string): string {
  const resolved = isAbsolute(filePath)
    ? filePath
    : resolve(agentCwd, filePath);
  const rel = relative(agentCwd, resolved);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path escapes agent working directory: ${filePath}`);
  }
  return resolved;
}

export function deleteFile(ctx: ToolContext) {
  return tool({
    description: `Delete a file from the filesystem.

Only deletes files (not directories). Path must stay within the agent working directory.
Fails loudly if the file does not exist.`,
    inputSchema: deleteFileInputSchema,
    execute: async ({ path: filePath }): Promise<DeleteFileResult> => {
      let target: string;
      try {
        target = resolveUnderCwd(ctx.agentCwd, filePath);
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          path: filePath,
        };
      }

      if (ctx.sandbox) {
        try {
          const check = await ctx.sandbox.execute(`test -f "${target}"`);
          if (check.exitCode !== 0) {
            return {
              success: false,
              error: `File not found: ${target}`,
              path: target,
            };
          }
          const result = await ctx.sandbox.execute(`rm "${target}"`);
          if (!result.success) {
            return {
              success: false,
              error: result.stderr || "Failed to delete file in sandbox",
              path: target,
            };
          }
          return { success: true, error: "", path: target };
        } catch (err: unknown) {
          return {
            success: false,
            error: err instanceof Error ? err.message : String(err),
            path: target,
          };
        }
      }

      try {
        await unlink(target);
        return { success: true, error: "", path: target };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          path: target,
        };
      }
    },
  });
}
