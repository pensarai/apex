import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

const readFileInputSchema = z.object({
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

type ReadFileInput = z.infer<typeof readFileInputSchema>;

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
      const { fs } = resolveBackends(ctx);
      return fs.read(path, { startLine, endLine });
    },
  });
}
