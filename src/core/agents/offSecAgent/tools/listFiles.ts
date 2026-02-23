import { tool } from "ai";
import { z } from "zod";
import { readdir, stat } from "fs/promises";
import { join } from "path";
import type { ToolContext } from "./types";

export const listFilesInputSchema = z.object({
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

export type ListFilesInput = z.infer<typeof listFilesInputSchema>;

export type ListFilesResult = {
  success: boolean;
  error: string;
  files: string[];
  directory: string;
  count: number;
};

async function listRecursive(
  dir: string,
  maxEntries: number,
): Promise<string[]> {
  const results: string[] = [];

  async function walk(current: string) {
    if (results.length >= maxEntries) return;
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (results.length >= maxEntries) break;
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        results.push(`${fullPath}/`);
        await walk(fullPath);
      } else {
        results.push(fullPath);
      }
    }
  }

  await walk(dir);
  return results;
}

export function listFiles(_ctx: ToolContext) {
  return tool({
    description: `List files and directories at a given path.

By default lists the immediate contents of the directory. Set recursive=true
to walk the tree (capped at 5 000 entries to avoid flooding context).

Each directory entry is suffixed with "/" for easy identification.`,
    inputSchema: listFilesInputSchema,
    execute: async ({
      directory,
      recursive = false,
    }): Promise<ListFilesResult> => {
      const dir = directory || process.cwd();

      try {
        const info = await stat(dir);
        if (!info.isDirectory()) {
          return {
            success: false,
            error: `${dir} is not a directory`,
            files: [],
            directory: dir,
            count: 0,
          };
        }

        const MAX_ENTRIES = 5_000;

        let files: string[];
        if (recursive) {
          files = await listRecursive(dir, MAX_ENTRIES);
        } else {
          const entries = await readdir(dir, { withFileTypes: true });
          files = entries.map((e) => {
            const name = join(dir, e.name);
            return e.isDirectory() ? `${name}/` : name;
          });
        }

        const truncated = files.length >= MAX_ENTRIES;

        return {
          success: true,
          error: truncated
            ? `Listing truncated at ${MAX_ENTRIES} entries — narrow the directory`
            : "",
          files,
          directory: dir,
          count: files.length,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          files: [],
          directory: dir,
          count: 0,
        };
      }
    },
  });
}
