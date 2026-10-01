import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ReadFileResult } from "./readFileImpl";
import { MAX_BYTE_WINDOW, MAX_LINE_CHARS } from "./readFileImpl";
import type { ToolContext } from "./types";

export type { ReadFileResult };

const readFileInputSchema = z.object({
  path: z
    .string()
    .describe(
      "Absolute or relative path to the file to read. Must be a file, not a directory.",
    ),
  startLine: z
    .number()
    .nullish()
    .describe(
      "1-based start line (inclusive). Omit or set null for byte mode or the beginning of the file.",
    ),
  endLine: z
    .number()
    .nullish()
    .describe(
      "1-based end line (inclusive). Omit or set null for byte mode or the end of the file.",
    ),
  byteOffset: z
    .number()
    .int()
    .min(0)
    .nullish()
    .describe(
      "0-based UTF-8 codepoint-aligned byte offset, paired with byteCount. Omit or set null for line reads. Use byte mode for minified single-line files; startLine and endLine must be omitted or null.",
    ),
  byteCount: z
    .number()
    .int()
    .min(1)
    .max(MAX_BYTE_WINDOW)
    .nullish()
    .describe(
      `Bytes to read from byteOffset (max ${MAX_BYTE_WINDOW}). Requires byteOffset. Omit or set null for line reads.`,
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Reading nginx config file')",
    ),
});

export function readFile(ctx: ToolContext) {
  return tool({
    description: `Read the contents of a file from the filesystem. This tool only works on files, NOT directories. To list directory contents, use the list_files tool instead.

Read tool-output: references returned by execute_command or grep to inspect saved
output. These references address only this agent's retained output, including
when commands run in a remote sandbox.

You can read the entire file or specify a line range using startLine / endLine
(both 1-based, inclusive). If only startLine is given, reads from that line to
the end. If only endLine is given, reads from the beginning to that line.
Choose one paging mode: omit or set byteOffset and byteCount to null for line
reads; omit or set startLine and endLine to null for byte reads. Never fill
inactive fields with placeholder numbers. Omit or set all four to null to
read from the beginning using the default bounded line reader.

Output lines are prefixed with their line number for easy reference. Reads are
bounded: a huge file returns a window plus truncation metadata instead of
buffering the whole file, and lines longer than ${MAX_LINE_CHARS} characters
are capped with an explicit marker (the read is marked truncated — use
byteOffset / byteCount for the dropped bytes). Byte windows must start on a
UTF-8 codepoint boundary and never split one: stoppedAtByte is the exact
resume cursor.`,
    inputSchema: readFileInputSchema,
    execute: async (input): Promise<ReadFileResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.read(input.path, {
        startLine: input.startLine ?? undefined,
        endLine: input.endLine ?? undefined,
        byteOffset: input.byteOffset ?? undefined,
        byteCount: input.byteCount ?? undefined,
      });
    },
  });
}
