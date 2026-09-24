import { randomBytes } from "node:crypto";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { resolveFilePath } from "./fileWorkspace";
import { compileGlobPattern } from "./globPattern";
import type { UnifiedSandbox } from "./sandbox";
import {
  SANDBOX_OP_TIMEOUT_SECONDS,
  sandboxOpError,
  WIN_SCRIPT_COMMAND,
  WIN_SCRIPT_PRELUDE,
  winScriptEnv,
} from "./sandboxScript";
import type { ToolContext } from "./types";

// Pruned by basename on every backend — equivalent to the previous
// "**/<name>/**" ignore list, applied while walking instead of after.
const IGNORED_DIR_NAMES = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
];

const MAX_RESULTS = 200;
// Enumeration bound shared by local and sandbox walks: matching past this
// many files reports possible incompleteness instead of unbounded scanning.
const MAX_SCAN_ENTRIES = 20_000;

const globInputSchema = z.object({
  pattern: z
    .string()
    .describe(
      'Relative glob pattern (e.g. "**/*.ts", "src/**/*.tsx", "**/package.json"). Supports *, ?, [...], {a,b}, and ** as full path segments. Absolute patterns and ".." segments are rejected.',
    ),
  path: z
    .string()
    .optional()
    .describe(
      "Directory to search from (absolute or relative to the agent cwd). Defaults to agent cwd.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Find all TypeScript source files')",
    ),
});

export type GlobResult = {
  success: boolean;
  error: string;
  files: string[];
  count: number;
  totalFound?: number;
  pattern: string;
  cwd: string;
};

type Enumeration = { entries: string[]; overflow: boolean };

/** Local walk: files only, ignore-named dirs pruned, symlink dirs not followed. */
async function enumerateLocal(
  root: string,
  signal?: AbortSignal,
): Promise<Enumeration> {
  const entries: string[] = [];

  async function walk(dir: string, prefix: string): Promise<void> {
    signal?.throwIfAborted();
    if (entries.length > MAX_SCAN_ENTRIES) return;
    let dirents: import("fs").Dirent[];
    try {
      dirents = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of dirents) {
      signal?.throwIfAborted();
      if (entry.isDirectory()) {
        if (IGNORED_DIR_NAMES.includes(entry.name)) continue;
        await walk(join(dir, entry.name), `${prefix}${entry.name}/`);
        continue;
      }
      if (entries.length > MAX_SCAN_ENTRIES) {
        return;
      }
      entries.push(`${prefix}${entry.name}`);
    }
  }

  await walk(root, "");
  return { entries, overflow: entries.length > MAX_SCAN_ENTRIES };
}

function posixGlobCommand(nonce: string): string {
  const prune = IGNORED_DIR_NAMES.map((n) => `-name ${JSON.stringify(n)}`).join(
    " -o ",
  );
  return [
    'cd "$APEX_GLOB_PATH" || exit 3',
    `find . -mindepth 1 -type d \\( ${prune} \\) -prune -o -type d -o -print | head -n ${MAX_SCAN_ENTRIES + 1}`,
    `echo "APEXGL-${nonce} end"`,
  ].join("\n");
}

// Windows walker: stack-based DFS, files only, ignore-named dirs and reparse
// points not descended, emissions capped, nonce marker proves completion.
const WIN_GLOB_SCRIPT = [
  WIN_SCRIPT_PRELUDE,
  "try{",
  "$p=[Environment]::GetEnvironmentVariable('APEX_GLOB_PATH')",
  "$cap=[int64][Environment]::GetEnvironmentVariable('APEX_GLOB_CAP')",
  "$nonce=[Environment]::GetEnvironmentVariable('APEX_GLOB_NONCE')",
  `$ignore=@(${IGNORED_DIR_NAMES.map((n) => `'${n}'`).join(",")})`,
  "$baseLen=$p.Length",
  "$emitted=[int64]0",
  "$stack=New-Object 'System.Collections.Generic.Stack[string]'",
  "$stack.Push($p)",
  "while($stack.Count -gt 0 -and $emitted -le $cap){",
  "$d=$stack.Pop()",
  "try{",
  "$di=New-Object IO.DirectoryInfo($d)",
  "foreach($e in $di.EnumerateFileSystemInfos()){",
  "$isLink=(($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)",
  // FileSystemInfo from the raw .NET enumerator: container detection via
  // Attributes, not the adapted PSIsContainer.
  "if((($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0)){",
  "if($isLink -or $ignore -contains $e.Name){continue}",
  "$stack.Push($e.FullName)",
  "continue",
  "}",
  "if($emitted -gt $cap){break}",
  "$rel=$e.FullName.Substring($baseLen).TrimStart([char]92,[char]47)",
  "[Console]::Out.WriteLine($rel)",
  "$emitted++",
  "}",
  "}catch{continue}",
  "}",
  '[Console]::Out.WriteLine("APEXGL-$nonce end")',
  "}catch{",
  "[Console]::Error.WriteLine($_.Exception.Message)",
  "exit 2",
  "}",
].join("\n");

async function enumerateSandbox(
  sandbox: UnifiedSandbox,
  root: string,
): Promise<Enumeration | { error: string }> {
  const nonce = randomBytes(8).toString("hex");
  const result =
    sandbox.type === "windows"
      ? await sandbox.execute(WIN_SCRIPT_COMMAND, {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars: {
            ...winScriptEnv(WIN_GLOB_SCRIPT),
            APEX_GLOB_PATH: root,
            APEX_GLOB_CAP: String(MAX_SCAN_ENTRIES),
            APEX_GLOB_NONCE: nonce,
          },
        })
      : await sandbox.execute(posixGlobCommand(nonce), {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars: { APEX_GLOB_PATH: root },
        });
  if (!result.success || result.exitCode !== 0) {
    return { error: sandboxOpError("glob", result) };
  }
  const lines = result.stdout.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const marker = lines.pop();
  if (marker !== `APEXGL-${nonce} end`) {
    return {
      error: `sandbox glob enumeration missing APEXGL-${nonce} completion marker: ${result.stdout.slice(0, 200)}`,
    };
  }
  return {
    // POSIX find prints "./"-prefixed paths; matching uses bare relative paths.
    entries: lines.map((line) =>
      line.startsWith("./") ? line.slice(2) : line,
    ),
    overflow: lines.length > MAX_SCAN_ENTRIES,
  };
}

function matchEntries(
  entries: string[],
  regexes: RegExp[],
  overflow: boolean,
  pattern: string,
  cwd: string,
): GlobResult {
  const matches = entries.filter((entry) =>
    regexes.some((regex) => regex.test(entry)),
  );
  const truncated = matches.length > MAX_RESULTS;
  const files = matches.slice(0, MAX_RESULTS).sort();
  return {
    success: true,
    error: overflow
      ? `results may be incomplete — scan capped at ${MAX_SCAN_ENTRIES} entries; narrow the pattern or path`
      : truncated
        ? `Showing ${MAX_RESULTS} of ${matches.length} matches — narrow the pattern`
        : "",
    files,
    count: files.length,
    totalFound: overflow ? undefined : truncated ? matches.length : undefined,
    pattern,
    cwd,
  };
}

export function globFiles(ctx: ToolContext) {
  return tool({
    description: `Find files by glob pattern under the agent working directory.

Examples:
- "**/*.ts" — all TypeScript files
- "src/**/*.{ts,tsx}" — sources under src/
- "**/package.json" — package manifests

Patterns are relative to the search root; absolute patterns and ".." segments
are rejected. Supports *, ?, [...], {a,b}, and ** as full path segments.

Skips common junk directories (node_modules, .git, dist, build, .next,
coverage, venv) and dotfiles. Results are capped at ${MAX_RESULTS}; narrow the
pattern if truncated.`,
    inputSchema: globInputSchema,
    execute: async ({ pattern, path }): Promise<GlobResult> => {
      let root = ctx.agentCwd;
      try {
        ctx.abortSignal?.throwIfAborted();
        const compiled = compileGlobPattern(pattern);
        if ("error" in compiled) throw new Error(compiled.error);
        root = await resolveFilePath(ctx, path ?? ".", { confineToCwd: true });
        ctx.abortSignal?.throwIfAborted();
        const enumeration = ctx.sandbox
          ? await enumerateSandbox(ctx.sandbox, root)
          : await enumerateLocal(root, ctx.abortSignal);
        ctx.abortSignal?.throwIfAborted();
        if ("error" in enumeration) throw new Error(enumeration.error);
        return matchEntries(
          enumeration.entries,
          compiled.regexes,
          enumeration.overflow,
          pattern,
          root,
        );
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          files: [],
          count: 0,
          pattern,
          cwd: root,
        };
      }
    },
  });
}
