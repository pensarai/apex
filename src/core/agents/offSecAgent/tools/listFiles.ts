import { tool } from "ai";
import { z } from "zod";
import { CAPS } from "../../../tools/backends/helpers";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

const listFilesInputSchema = z.object({
  directory: z
    .string()
    .optional()
    .describe(
      "Absolute or relative path to the directory to list (defaults to current working directory)",
    ),
  recursive: z
    .boolean()
    .optional()
    .describe("If true, list files recursively (default: false)"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Listing files in /etc/nginx')",
    ),
});

type ListFilesInput = z.infer<typeof listFilesInputSchema>;

export type ListFilesResult = {
  success: boolean;
  error: string;
  files: string[];
  directory: string;
  count: number;
  totalFound?: number;
};

export function listFiles(ctx: ToolContext) {
  return tool({
    description: `List files and directories at a given path.

By default lists the immediate contents of the directory. Set recursive=true
to walk the tree. Returns paths relative to the listed directory.

Recursive listings are capped at ${CAPS.LIST_MAX_RECURSIVE} entries. Use grep or
read_file for targeted exploration instead of recursive listing on large trees.

Each directory entry is suffixed with "/" for easy identification.`,
    inputSchema: listFilesInputSchema,
    execute: async ({
      directory,
      recursive = false,
    }): Promise<ListFilesResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.list(directory ?? "", { recursive });
    },
  });
}
