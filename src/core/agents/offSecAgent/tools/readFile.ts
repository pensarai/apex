import { tool } from "ai";
import { z } from "zod";
import { readFile as fsReadFile } from "fs/promises";
import { resolve, isAbsolute } from "path";
import type { ToolContext } from "./types";

export const readFileInputSchema = z.object({
  path: z
    .string()
    .describe(
      "Absolute or relative path to the file to read. Must be a file, not a directory.",
    ),
  startLine: z
    .number()
    .optional()
    .describe("1-based line number to start reading from (inclusive)"),
  endLine: z
    .number()
    .optional()
    .describe("1-based line number to stop reading at (inclusive)"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Reading nginx config file')",
    ),
});

export type ReadFileInput = z.infer<typeof readFileInputSchema>;

export type ReadFileResult = {
  success: boolean;
  error: string;
  content: string;
  path: string;
  totalLines?: number;
  linesReturned?: number;
};

export function readFile(ctx: ToolContext) {
  return tool({
    description: `Read the contents of a file from the filesystem. This tool only works on files, NOT directories. To list directory contents, use the list_files tool instead.

You can read the entire file or specify a line range using startLine / endLine
(both 1-based, inclusive). If only startLine is given, reads from that line to
the end. If only endLine is given, reads from the beginning to that line.

Output lines are prefixed with their line number for easy reference.`,
    inputSchema: readFileInputSchema,
    execute: async ({ path, startLine, endLine }): Promise<ReadFileResult> => {
      const resolved = isAbsolute(path) ? path : resolve(ctx.agentCwd, path);
      try {
        const raw = await fsReadFile(resolved, "utf-8");
        const allLines = raw.split("\n");
        const totalLines = allLines.length;

        const start = startLine ? Math.max(1, startLine) : 1;
        const end = endLine ? Math.min(totalLines, endLine) : totalLines;

        const selected = allLines.slice(start - 1, end);
        const numbered = selected
          .map((line, i) => `${String(start + i).padStart(6)}|${line}`)
          .join("\n");

        const content =
          numbered.length > 100_000
            ? `${numbered.substring(0, 100_000)}\n\n(truncated — use startLine/endLine to paginate)`
            : numbered;

        return {
          success: true,
          error: "",
          content,
          path,
          totalLines,
          linesReturned: selected.length,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          content: "",
          path,
        };
      }
    },
  });
}
