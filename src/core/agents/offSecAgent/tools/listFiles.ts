import { readdir, stat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { tool } from "ai";
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
  /** Set when `totalFound` is a lower bound (the walk stopped early), not an exact count. */
  totalFoundLowerBound?: boolean;
  truncated?: boolean;
};

const MAX_RECURSIVE = 200;
const MAX_NON_RECURSIVE = 500;

/**
 * Depth-first readdir walk that stops at the (maxEntries + 1)-th collected
 * path — the overflow witness — instead of walking the whole tree for an
 * exact total. First `maxEntries` paths match the unbounded walk on the same
 * runtime (shared readdir order); visited directories still pay their full
 * native width enumeration (docs/performance/pr-08-listing-result-limit.md).
 */
export async function listRecursive(
  dir: string,
  maxEntries: number,
  signal?: AbortSignal,
): Promise<{
  paths: string[];
  truncated: boolean;
}> {
  const results: string[] = [];

  async function walk(current: string): Promise<void> {
    if (results.length > maxEntries) return;
    signal?.throwIfAborted();
    let entries: import("fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      // Unreadable or vanished directories are skipped like before — but
      // cancellation that landed during the failed read must not be
      // swallowed with the filesystem error.
      signal?.throwIfAborted();
      return;
    }
    // Cancellation can land while the enumeration is in flight, including
    // for an empty result; the walk must never unwind into a "complete"
    // listing after an abort was observed here.
    signal?.throwIfAborted();
    for (const entry of entries) {
      if (results.length > maxEntries) return;
      signal?.throwIfAborted();
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
  return {
    paths: results,
    truncated: results.length > maxEntries,
  };
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
      ctx.abortSignal?.throwIfAborted();
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
          ctx.abortSignal?.throwIfAborted();
          const { paths, truncated } = await listRecursive(
            dir,
            MAX_RECURSIVE,
            ctx.abortSignal,
          );
          const relPaths = toRelative(dir, paths.slice(0, MAX_RECURSIVE));
          return {
            success: true,
            error: truncated
              ? `Listing truncated at ${MAX_RECURSIVE} entries — narrow the directory or use grep`
              : "",
            files: relPaths,
            directory: dir,
            count: relPaths.length,
            totalFound: truncated ? paths.length : undefined,
            totalFoundLowerBound: truncated || undefined,
            truncated: truncated || undefined,
          };
        }

        const entries = await readdir(dir, { withFileTypes: true });
        ctx.abortSignal?.throwIfAborted();
        const truncated = entries.length > MAX_NON_RECURSIVE;
        // Slice before mapping so only the returned paths are materialized.
        const fullPaths = entries.slice(0, MAX_NON_RECURSIVE).map((e) => {
          const name = join(dir, e.name);
          return e.isDirectory() ? `${name}/` : name;
        });
        const relPaths = toRelative(dir, fullPaths);

        return {
          success: true,
          error: truncated
            ? `Showing ${MAX_NON_RECURSIVE} of ${entries.length} entries`
            : "",
          files: relPaths,
          directory: dir,
          count: relPaths.length,
          totalFound: truncated ? entries.length : undefined,
          truncated: truncated || undefined,
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
