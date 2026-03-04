import { tool } from "ai";
import { z } from "zod";
import { writeFile, mkdir } from "fs/promises";
import { dirname } from "path";
import { existsSync } from "fs";
import type { ToolContext } from "./types";

export const createFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path for the new file"),
  content: z.string().describe("Content to write to the file"),
  overwrite: z
    .boolean()
    .optional()
    .describe("If true, overwrite the file if it already exists (default: false)"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Creating security middleware file')",
    ),
});

export type CreateFileInput = z.infer<typeof createFileInputSchema>;

export type CreateFileResult = {
  success: boolean;
  error: string;
  path: string;
};

export function createFile(_ctx: ToolContext) {
  return tool({
    description: `Create a new file with the given content.

By default, refuses to overwrite an existing file. Set overwrite=true to replace
an existing file's content entirely.

Parent directories are created automatically if they don't exist.`,
    inputSchema: createFileInputSchema,
    execute: async ({
      path: filePath,
      content,
      overwrite = false,
    }): Promise<CreateFileResult> => {
      try {
        if (!overwrite && existsSync(filePath)) {
          return {
            success: false,
            error: `File already exists: ${filePath}. Set overwrite=true to replace it.`,
            path: filePath,
          };
        }

        await mkdir(dirname(filePath), { recursive: true });
        await writeFile(filePath, content, "utf-8");

        return {
          success: true,
          error: "",
          path: filePath,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          path: filePath,
        };
      }
    },
  });
}
