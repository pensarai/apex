import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

const createFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path for the new file"),
  content: z.string().describe("Content to write to the file"),
  overwrite: z
    .boolean()
    .optional()
    .describe(
      "If true, overwrite the file if it already exists (default: false)",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Creating security middleware file')",
    ),
});

type CreateFileInput = z.infer<typeof createFileInputSchema>;

export type CreateFileResult = {
  success: boolean;
  error: string;
  path: string;
};

export function createFile(ctx: ToolContext) {
  return tool({
    description: `Create a new file with the given content.

By default, refuses to overwrite an existing file. Set overwrite=true to replace
an existing file's content entirely.

Parent directories are created automatically if they don't exist.`,
    inputSchema: createFileInputSchema,
    execute: async ({
      path,
      content,
      overwrite = false,
    }): Promise<CreateFileResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.write(path, content, {
        mode: overwrite ? "overwrite" : "create",
      });
    },
  });
}
