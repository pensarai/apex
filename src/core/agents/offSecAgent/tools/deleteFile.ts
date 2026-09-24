import { tool } from "ai";
import { z } from "zod";
import {
  deleteWorkspaceFile,
  readWorkspaceFile,
  resolveFilePath,
} from "./fileWorkspace";
import type { ToolContext } from "./types";

const deleteFileInputSchema = z.object({
  path: z.string().describe("Path to the text file within the file workspace"),
  toolCallDescription: z
    .string()
    .describe("A concise description of this deletion"),
});

export type DeleteFileResult = {
  success: boolean;
  error: string;
  path: string;
};

export function deleteFile(ctx: ToolContext) {
  return tool({
    description: `Delete an ordinary UTF-8 text file within the agent's file workspace (or working directory when no file workspace is set).
Missing files, directories, binary files, and files larger than 1 MiB fail explicitly.
If contents change while preparing the deletion, re-read before retrying.`,
    inputSchema: deleteFileInputSchema,
    execute: async ({ path }): Promise<DeleteFileResult> => {
      let resolved = path;
      try {
        resolved = await resolveFilePath(ctx, path, { confineToCwd: true });
        const expected = await readWorkspaceFile(ctx, resolved);
        await deleteWorkspaceFile(ctx, resolved, { expected });
        return { success: true, error: "", path: resolved };
      } catch (error: unknown) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
          path: resolved,
        };
      }
    },
  });
}
