import { tool } from "ai";
import { z } from "zod";
import { readFile, writeFile } from "fs/promises";
import type { ToolContext } from "./types";

export const updateFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path to the file to update"),
  oldContent: z
    .string()
    .describe(
      "The exact string to find in the file. Must match character-for-character including whitespace and indentation.",
    ),
  newContent: z
    .string()
    .describe("The replacement string that will replace oldContent"),
  replaceAll: z
    .boolean()
    .optional()
    .describe(
      "If true, replace ALL occurrences of oldContent. Otherwise replace only the first (default: false).",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Replacing vulnerable SQL query with parameterized version')",
    ),
});

export type UpdateFileInput = z.infer<typeof updateFileInputSchema>;

export type UpdateFileResult = {
  success: boolean;
  error: string;
  path: string;
  replacements: number;
};

export function updateFile(_ctx: ToolContext) {
  return tool({
    description: `Update a file by replacing exact string matches.

Performs a search-and-replace on the file: finds \`oldContent\` and replaces it
with \`newContent\`. The match is exact (character-for-character), so include
enough surrounding context in oldContent to ensure a unique match.

By default replaces only the first occurrence. Set replaceAll=true to replace
every occurrence.

Returns the number of replacements made. If oldContent is not found, the
operation fails with an error — double-check whitespace and indentation.`,
    inputSchema: updateFileInputSchema,
    execute: async ({
      path: filePath,
      oldContent,
      newContent,
      replaceAll = false,
    }): Promise<UpdateFileResult> => {
      try {
        const content = await readFile(filePath, "utf-8");

        if (!content.includes(oldContent)) {
          return {
            success: false,
            error: `oldContent not found in ${filePath}. Ensure the string matches exactly, including whitespace and indentation.`,
            path: filePath,
            replacements: 0,
          };
        }

        let updated: string;
        let replacements: number;

        if (replaceAll) {
          const parts = content.split(oldContent);
          replacements = parts.length - 1;
          updated = parts.join(newContent);
        } else {
          replacements = 1;
          updated = content.replace(oldContent, newContent);
        }

        await writeFile(filePath, updated, "utf-8");

        return {
          success: true,
          error: "",
          path: filePath,
          replacements,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          path: filePath,
          replacements: 0,
        };
      }
    },
  });
}
