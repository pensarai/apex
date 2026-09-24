import { tool } from "ai";
import { z } from "zod";
import { resolveFilePath, writeWorkspaceFile } from "./fileWorkspace";
import type { ToolContext } from "./types";

const createFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path in the file workspace"),
  content: z.string().describe("UTF-8 text to write (maximum 1 MiB)"),
  overwrite: z
    .boolean()
    .optional()
    .describe("Explicitly replace an existing text file (default: false)"),
  toolCallDescription: z
    .string()
    .describe("A concise description of this file creation"),
});

export type CreateFileResult = {
  success: boolean;
  error: string;
  path: string;
};

export function createFile(ctx: ToolContext) {
  return tool({
    description: `Create a UTF-8 text file in the agent's runtime.
Relative paths use the configured file workspace, otherwise the working directory.
A configured file workspace confines all paths; otherwise absolute paths are allowed.
Parent directories are created as needed. Existing files are preserved unless
overwrite=true. Concurrent exclusive creation has one winner. Maximum: 1 MiB.
Use update_file or apply_patch for changes to an existing file.`,
    inputSchema: createFileInputSchema,
    execute: async ({
      path,
      content,
      overwrite = false,
    }): Promise<CreateFileResult> => {
      let resolved = path;
      try {
        resolved = await resolveFilePath(ctx, path);
        await writeWorkspaceFile(ctx, resolved, content, {
          expected: overwrite ? undefined : null,
        });
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
