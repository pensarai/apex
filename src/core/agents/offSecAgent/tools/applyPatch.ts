import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

const applyPatchInputSchema = z.object({
  patch: z
    .string()
    .describe(
      "Unified diff to apply. May contain one or more file hunks (---/+++/@@). Paths are relative to the agent working directory unless absolute.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Apply parameterized-query fix across auth handlers')",
    ),
});

export type FilePatchResult = {
  path: string;
  success: boolean;
  error?: string;
  hunksApplied?: number;
};

export type ApplyPatchResult = {
  success: boolean;
  error: string;
  files: FilePatchResult[];
};

type Hunk = {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: string[];
};

type FileDiff = {
  oldPath: string;
  newPath: string;
  hunks: Hunk[];
  isNew: boolean;
  isDelete: boolean;
};

function stripPrefix(p: string): string {
  if (p.startsWith("a/") || p.startsWith("b/")) return p.slice(2);
  return p;
}

/**
 * Parse a unified diff into per-file diffs. Fails loudly on malformed input.
 */
export function parseUnifiedDiff(patch: string): FileDiff[] {
  const lines = patch.replace(/\r\n/g, "\n").split("\n");
  const files: FileDiff[] = [];
  let i = 0;

  while (i < lines.length) {
    // Skip empty / git headers until a --- line
    while (
      i < lines.length &&
      !lines[i].startsWith("--- ") &&
      !lines[i].startsWith("diff --git ")
    ) {
      i++;
    }
    if (i >= lines.length) break;

    if (lines[i].startsWith("diff --git ")) {
      i++;
      continue;
    }

    const oldLine = lines[i];
    if (!oldLine.startsWith("--- ")) {
      throw new Error(`Expected "---" file header at line ${i + 1}`);
    }
    i++;
    if (i >= lines.length || !lines[i].startsWith("+++ ")) {
      throw new Error(`Expected "+++" file header after "---" at line ${i}`);
    }
    const newLine = lines[i];
    i++;

    const oldPathRaw = oldLine.slice(4).split("\t")[0].trim();
    const newPathRaw = newLine.slice(4).split("\t")[0].trim();
    const isNew = oldPathRaw === "/dev/null";
    const isDelete = newPathRaw === "/dev/null";
    const oldPath = isNew ? "" : stripPrefix(oldPathRaw);
    const newPath = isDelete ? "" : stripPrefix(newPathRaw);

    const hunks: Hunk[] = [];
    while (i < lines.length && lines[i].startsWith("@@ ")) {
      const header = lines[i];
      const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(header);
      if (!match) {
        throw new Error(`Malformed hunk header: ${header}`);
      }
      i++;
      const hunkLines: string[] = [];
      while (
        i < lines.length &&
        !lines[i].startsWith("@@ ") &&
        !lines[i].startsWith("--- ") &&
        !lines[i].startsWith("diff --git ")
      ) {
        const l = lines[i];
        if (
          l.startsWith(" ") ||
          l.startsWith("+") ||
          l.startsWith("-") ||
          l === "\\ No newline at end of file"
        ) {
          hunkLines.push(l);
          i++;
        } else if (l === "") {
          // Trailing blank between files — stop hunk
          break;
        } else {
          throw new Error(`Unexpected line in hunk: ${l}`);
        }
      }
      hunks.push({
        oldStart: Number(match[1]),
        oldCount: match[2] !== undefined ? Number(match[2]) : 1,
        newStart: Number(match[3]),
        newCount: match[4] !== undefined ? Number(match[4]) : 1,
        lines: hunkLines,
      });
    }

    if (hunks.length === 0 && !isNew && !isDelete) {
      throw new Error(
        `No hunks found for file ${newPath || oldPath || "(unknown)"}`,
      );
    }

    files.push({ oldPath, newPath, hunks, isNew, isDelete });
  }

  if (files.length === 0) {
    throw new Error("Patch contained no file diffs");
  }

  return files;
}

function resolveUnderCwd(agentCwd: string, filePath: string): string {
  const resolved = isAbsolute(filePath)
    ? filePath
    : resolve(agentCwd, filePath);
  const rel = relative(agentCwd, resolved);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path escapes agent working directory: ${filePath}`);
  }
  return resolved;
}

/**
 * Apply hunks to file content. Throws if context does not match exactly.
 */
export function applyHunksToContent(content: string, hunks: Hunk[]): string {
  // Normalize to lines without retaining a trailing empty from final newline
  // so index math matches unified-diff 1-based line numbers.
  const endsWithNewline = content.endsWith("\n");
  const lines =
    content === ""
      ? []
      : content.endsWith("\n")
        ? content.slice(0, -1).split("\n")
        : content.split("\n");

  // Apply from bottom to top so earlier line numbers stay valid.
  const ordered = [...hunks].sort((a, b) => b.oldStart - a.oldStart);

  for (const hunk of ordered) {
    const startIdx = Math.max(0, hunk.oldStart - 1);
    let cursor = startIdx;
    const replacement: string[] = [];

    for (const raw of hunk.lines) {
      if (raw === "\\ No newline at end of file") continue;
      const tag = raw[0];
      const text = raw.slice(1);
      if (tag === " " || tag === "-") {
        if (cursor >= lines.length || lines[cursor] !== text) {
          const actual = cursor < lines.length ? lines[cursor] : "<EOF>";
          throw new Error(
            `Hunk context mismatch at line ${cursor + 1}: expected ${JSON.stringify(text)}, got ${JSON.stringify(actual)}`,
          );
        }
        if (tag === " ") {
          replacement.push(text);
        }
        cursor++;
      } else if (tag === "+") {
        replacement.push(text);
      } else {
        throw new Error(`Invalid hunk line prefix: ${raw}`);
      }
    }

    const endIdx = cursor;
    lines.splice(startIdx, endIdx - startIdx, ...replacement);
  }

  // Unified diffs imply a trailing newline for non-empty text files.
  if (lines.length === 0) return endsWithNewline ? "\n" : "";
  return `${lines.join("\n")}\n`;
}

async function readLocal(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return null;
  }
}

async function writeLocal(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, "utf-8");
}

async function readViaSandbox(
  ctx: ToolContext,
  path: string,
): Promise<string | null> {
  const result = await ctx.sandbox!.execute(
    `test -f "${path}" && cat "${path}" | base64 -w 0`,
  );
  if (!result.success || !result.stdout.trim()) {
    // Distinguish missing vs empty
    const exists = await ctx.sandbox!.execute(`test -f "${path}"`);
    if (exists.exitCode !== 0) return null;
    return "";
  }
  return Buffer.from(result.stdout.trim(), "base64").toString("utf-8");
}

async function writeViaSandbox(
  ctx: ToolContext,
  path: string,
  content: string,
): Promise<void> {
  const dir = dirname(path);
  await ctx.sandbox!.execute(`mkdir -p "${dir}"`);
  const b64 = Buffer.from(content).toString("base64");
  const result = await ctx.sandbox!.execute(
    `echo "${b64}" | base64 -d > "${path}"`,
  );
  if (!result.success) {
    throw new Error(result.stderr || `Failed to write ${path} in sandbox`);
  }
}

async function deleteViaSandbox(ctx: ToolContext, path: string): Promise<void> {
  const result = await ctx.sandbox!.execute(`rm "${path}"`);
  if (!result.success) {
    throw new Error(result.stderr || `Failed to delete ${path} in sandbox`);
  }
}

export function applyPatch(ctx: ToolContext) {
  return tool({
    description: `Apply a unified diff patch to one or more files.

Use this for multi-hunk or multi-file edits. For a single small string replace,
prefer update_file.

The patch must be a standard unified diff with ---/+++ headers and @@ hunks.
Context lines must match the current file contents exactly — the tool fails
loudly on mismatch and does not partially apply remaining files after a failure
within a file. Paths must stay under the agent working directory.

Example:
\`\`\`
--- a/src/auth.ts
+++ b/src/auth.ts
@@ -10,7 +10,7 @@
  function login(user, pass) {
-   query = "SELECT * FROM users WHERE name='" + user + "'"
+   query = db.prepare("SELECT * FROM users WHERE name=?")
  }
\`\`\``,
    inputSchema: applyPatchInputSchema,
    execute: async ({ patch }): Promise<ApplyPatchResult> => {
      let files: FileDiff[];
      try {
        files = parseUnifiedDiff(patch);
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          files: [],
        };
      }

      const results: FilePatchResult[] = [];

      for (const file of files) {
        const displayPath = file.newPath || file.oldPath;
        try {
          const targetPath = resolveUnderCwd(
            ctx.agentCwd,
            file.isDelete ? file.oldPath : file.newPath || file.oldPath,
          );

          if (file.isDelete) {
            if (ctx.sandbox) {
              await deleteViaSandbox(ctx, targetPath);
            } else {
              await unlink(targetPath);
            }
            results.push({
              path: displayPath,
              success: true,
              hunksApplied: 0,
            });
            continue;
          }

          const existing = ctx.sandbox
            ? await readViaSandbox(ctx, targetPath)
            : await readLocal(targetPath);

          if (file.isNew) {
            if (existing !== null) {
              throw new Error(
                `Cannot create ${targetPath}: file already exists`,
              );
            }
            const created = applyHunksToContent("", file.hunks);
            if (ctx.sandbox) {
              await writeViaSandbox(ctx, targetPath, created);
            } else {
              await writeLocal(targetPath, created);
            }
            results.push({
              path: displayPath,
              success: true,
              hunksApplied: file.hunks.length,
            });
            continue;
          }

          if (existing === null) {
            throw new Error(`File not found: ${targetPath}`);
          }

          const updated = applyHunksToContent(existing, file.hunks);
          if (ctx.sandbox) {
            await writeViaSandbox(ctx, targetPath, updated);
          } else {
            await writeLocal(targetPath, updated);
          }
          results.push({
            path: displayPath,
            success: true,
            hunksApplied: file.hunks.length,
          });
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          results.push({
            path: displayPath,
            success: false,
            error: message,
          });
          return {
            success: false,
            error: `Failed applying patch to ${displayPath}: ${message}`,
            files: results,
          };
        }
      }

      return {
        success: true,
        error: "",
        files: results,
      };
    },
  });
}
