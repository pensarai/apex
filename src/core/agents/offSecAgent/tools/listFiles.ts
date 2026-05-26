import { tool } from "ai";
import { readdir, stat } from "fs/promises";
import { isAbsolute, join, relative, resolve } from "path";
import { z } from "zod";
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

const MAX_RECURSIVE = 200;
const MAX_NON_RECURSIVE = 500;

async function listRecursive(
  dir: string,
  maxEntries: number,
): Promise<{ paths: string[]; total: number }> {
  const results: string[] = [];
  let total = 0;

  async function walk(current: string) {
    let entries: import("fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      total++;
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (results.length < maxEntries) results.push(`${fullPath}/`);
        await walk(fullPath);
      } else {
        if (results.length < maxEntries) results.push(fullPath);
      }
    }
  }

  await walk(dir);
  return { paths: results, total };
}

function toRelative(base: string, paths: string[]): string[] {
  return paths.map((p) => {
    const isDir = p.endsWith("/");
    const rel = relative(base, isDir ? p.slice(0, -1) : p);
    return isDir ? `${rel}/` : rel;
  });
}

export function listFiles(ctx: ToolContext) {
  return tool({
    description: `List files and directories at a given path.

By default lists the immediate contents of the directory. Set recursive=true
to walk the tree. Returns paths relative to the listed directory.

Recursive listings are capped at ${MAX_RECURSIVE} entries. Use grep or
read_file for targeted exploration instead of recursive listing on large trees.

Each directory entry is suffixed with "/" for easy identification.`,
    inputSchema: listFilesInputSchema,
    execute: async ({
      directory,
      recursive = false,
    }): Promise<ListFilesResult> => {
      const dir = directory
        ? isAbsolute(directory)
          ? directory
          : resolve(ctx.agentCwd, directory)
        : ctx.agentCwd;

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

        if (recursive) {
          const { paths, total } = await listRecursive(dir, MAX_RECURSIVE);
          const relPaths = toRelative(dir, paths);
          return {
            success: true,
            error:
              total > MAX_RECURSIVE
                ? `Showing ${MAX_RECURSIVE} of ${total} entries — narrow the directory or use grep`
                : "",
            files: relPaths,
            directory: dir,
            count: relPaths.length,
            totalFound: total > MAX_RECURSIVE ? total : undefined,
          };
        }

        const entries = await readdir(dir, { withFileTypes: true });
        const fullPaths = entries.map((e) => {
          const name = join(dir, e.name);
          return e.isDirectory() ? `${name}/` : name;
        });

        const capped = fullPaths.slice(0, MAX_NON_RECURSIVE);
        const relPaths = toRelative(dir, capped);

        return {
          success: true,
          error:
            entries.length > MAX_NON_RECURSIVE
              ? `Showing ${MAX_NON_RECURSIVE} of ${entries.length} entries`
              : "",
          files: relPaths,
          directory: dir,
          count: relPaths.length,
          totalFound:
            entries.length > MAX_NON_RECURSIVE ? entries.length : undefined,
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
