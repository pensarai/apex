import { tool } from "ai";
import { z } from "zod";
import { resolveContained } from "../../../tools/backends/helpers";
import { resolveBackends } from "../../../tools/backends/resolve";
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

export function deleteFile(ctx: ToolContext) {
  return tool({
    description: `Delete a file from the filesystem.

Only deletes files (not directories). Path must stay within the agent working directory.
Fails loudly if the file does not exist.`,
    inputSchema: deleteFileInputSchema,
    execute: async ({ path }): Promise<DeleteFileResult> => {
      // Local runs echo the resolved path; a host backend resolves its own.
      let echoed = path;
      if (!ctx.backends) {
        try {
          echoed = resolveContained(ctx.agentCwd, path);
        } catch (err: unknown) {
          return {
            success: false,
            error: err instanceof Error ? err.message : String(err),
            path,
          };
        }
      }
      try {
        await resolveBackends(ctx).fs.delete(path);
        return { success: true, error: "", path: echoed };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          path: echoed,
        };
      }
    },
  });
}
