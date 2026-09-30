import { tool } from "ai";
import { z } from "zod";
import {
  readWorkspaceFile,
  resolveFilePath,
  writeWorkspaceFile,
} from "./fileWorkspace";
import type { ToolContext } from "./types";

const updateFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path in the file workspace"),
  oldContent: z
    .string()
    .min(1)
    .describe(
      "Nonempty text to replace; include unique context. LF is adapted to CRLF in uniformly CRLF files",
    ),
  newContent: z
    .string()
    .describe(
      "Literal replacement text, with LF adapted to CRLF in uniformly CRLF files",
    ),
  replaceAll: z
    .boolean()
    .optional()
    .describe(
      "Replace every non-overlapping occurrence; otherwise the match must be unique (default: false)",
    ),
  toolCallDescription: z
    .string()
    .describe("A concise description of this edit"),
});

export type UpdateFileResult = {
  success: boolean;
  error: string;
  path: string;
  replacements: number;
};

export function updateFile(ctx: ToolContext) {
  return tool({
    description: `Replace exact text in a UTF-8 file in the agent's runtime.
Relative paths use the configured file workspace, otherwise the working directory.
A configured file workspace confines all paths; otherwise absolute paths are allowed.
The default requires a unique match. Ambiguous or empty searches change nothing:
read the relevant lines and include more context, or explicitly set replaceAll.
Replacement text is literal. For uniformly CRLF files, LF input is converted to
CRLF; untouched content and BOM are preserved. Mixed line endings require an
exact match. If the file changes while preparing the edit, re-read and retry.
An unchanged replacement succeeds with zero replacements. Maximum file size: 1 MiB.`,
    inputSchema: updateFileInputSchema,
    execute: async ({
      path,
      oldContent,
      newContent,
      replaceAll = false,
    }): Promise<UpdateFileResult> => {
      let resolved = path;
      try {
        if (!oldContent)
          throw new Error(
            "oldContent must be nonempty; read the file and supply an exact match",
          );
        resolved = await resolveFilePath(ctx, path);
        const original = await readWorkspaceFile(ctx, resolved);
        const crlf = original.includes("\r\n") && !/(?<!\r)\n/.test(original);
        const normalize = (text: string) =>
          crlf ? text.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n") : text;
        const search = normalize(oldContent);
        const replacement = normalize(newContent);
        const first = original.indexOf(search);
        if (first < 0)
          throw new Error(
            "oldContent not found; read the file and match its exact text and indentation",
          );
        if (!replaceAll && original.indexOf(search, first + 1) >= 0)
          throw new Error(
            "oldContent is ambiguous; include more context or explicitly set replaceAll=true",
          );
        if (search === replacement)
          return { success: true, error: "", path: resolved, replacements: 0 };
        const parts = original.split(search);
        const updated = replaceAll
          ? parts.join(replacement)
          : original.slice(0, first) +
            replacement +
            original.slice(first + search.length);
        await writeWorkspaceFile(ctx, resolved, updated, {
          expected: original,
        });
        return {
          success: true,
          error: "",
          path: resolved,
          replacements: replaceAll ? parts.length - 1 : 1,
        };
      } catch (error: unknown) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
          path: resolved,
          replacements: 0,
        };
      }
    },
  });
}
