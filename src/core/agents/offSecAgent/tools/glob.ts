import { randomBytes } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { resolveFilePath } from "./fileWorkspace";
import { compileGlobPattern, type GlobPattern } from "./globPattern";
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
type CompiledPattern = Exclude<GlobPattern, { error: string }>;

/** Local walk: files only, ignore-named dirs pruned, symlink dirs not followed. */
async function enumerateLocal(
  root: string,
  pattern: CompiledPattern,
  signal?: AbortSignal,
): Promise<Enumeration> {
  if (!(await stat(root)).isDirectory()) {
    throw new Error(`${root} is not a directory`);
  }
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
      const relative = `${prefix}${entry.name}`;
      if (entry.isDirectory() || entry.name.startsWith(".")) {
        const allowed = entry.isDirectory()
          ? pattern.directoryRegexes
          : pattern.regexes;
        if (!allowed.some((regex) => regex.test(relative))) continue;
      }
      if (entry.isDirectory()) {
        if (entry.isSymbolicLink()) continue;
        if (IGNORED_DIR_NAMES.includes(entry.name)) continue;
        await walk(join(dir, entry.name), `${relative}/`);
        continue;
      }
      if (entries.length > MAX_SCAN_ENTRIES) {
        return;
      }
      entries.push(relative);
    }
  }

  await walk(root, "");
  return { entries, overflow: entries.length > MAX_SCAN_ENTRIES };
}

// Python is also used by sandbox path resolution. Prune hidden paths during
// enumeration, before unrelated files can consume the shared scan budget.
const POSIX_GLOB_COMMAND = `python3 - <<'APEX_GLOB_PY'
import base64, json, os, re
def utf16_units(text):
    # JS and .NET regexes match UTF-16 units, including for ? and classes.
    data = text.encode('utf-16-le', errors='surrogatepass')
    return ''.join(chr(data[i] | (data[i + 1] << 8)) for i in range(0, len(data), 2))
payload = ''.join(os.environ['APEX_GLOB_RULES_' + str(i)] for i in range(int(os.environ['APEX_GLOB_RULES_COUNT'])))
rules = json.loads(base64.b64decode(payload))
directories = [re.compile(utf16_units(source)) for source in rules['directories']]
files = [re.compile(utf16_units(source)) for source in rules['files']]
ignored = set(${JSON.stringify(IGNORED_DIR_NAMES)})
cap = int(os.environ['APEX_GLOB_CAP'])
root = os.environ['APEX_GLOB_PATH']
if not os.path.isdir(root):
    raise NotADirectoryError(root + ' is not a directory')
stack = [(root, '')]
emitted = 0
while stack and emitted <= cap:
    directory, prefix = stack.pop()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                relative = prefix + entry.name
                is_directory = entry.is_dir(follow_symlinks=False)
                if is_directory or entry.name.startswith('.'):
                    allowed = directories if is_directory else files
                    if not any(regex.search(utf16_units(relative)) for regex in allowed):
                        continue
                if is_directory:
                    if entry.name not in ignored:
                        stack.append((entry.path, relative + '/'))
                    continue
                print(relative)
                emitted += 1
                if emitted > cap:
                    break
    except OSError:
        continue
print('APEXGL-' + os.environ['APEX_GLOB_NONCE'] + ' end')
APEX_GLOB_PY`;

// Windows walker: stack-based DFS, files only, ignore-named dirs and reparse
// points not descended, emissions capped, nonce marker proves completion.
const WIN_GLOB_SCRIPT = [
  WIN_SCRIPT_PRELUDE,
  "try{",
  "$p=[Environment]::GetEnvironmentVariable('APEX_GLOB_PATH')",
  'if(-not [IO.Directory]::Exists($p)){throw "$p is not a directory"}',
  "$cap=[int64][Environment]::GetEnvironmentVariable('APEX_GLOB_CAP')",
  "$nonce=[Environment]::GetEnvironmentVariable('APEX_GLOB_NONCE')",
  "$payload=''",
  "for($i=0;$i -lt [int]$env:APEX_GLOB_RULES_COUNT;$i++){$payload+=[Environment]::GetEnvironmentVariable('APEX_GLOB_RULES_'+$i)}",
  "$rules=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)))",
  "$directories=@($rules.directories | ForEach-Object {New-Object regex($_)})",
  "$files=@($rules.files | ForEach-Object {New-Object regex($_)})",
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
  "$rel=$e.FullName.Substring($baseLen).TrimStart([char]92,[char]47).Replace([char]92,[char]47)",
  "$isDirectory=(($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0)",
  "if($isDirectory -or $e.Name.StartsWith('.')){",
  "$allowed=$files; if($isDirectory){$allowed=$directories}",
  "$allowedMatch=$false; foreach($regex in $allowed){if($regex.IsMatch($rel)){$allowedMatch=$true; break}}",
  "if(-not $allowedMatch){continue}",
  "}",
  "$isLink=(($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)",
  // FileSystemInfo from the raw .NET enumerator: container detection via
  // Attributes, not the adapted PSIsContainer.
  "if($isDirectory){",
  "if($isLink -or $ignore -contains $e.Name){continue}",
  "$stack.Push($e.FullName)",
  "continue",
  "}",
  "if($emitted -gt $cap){break}",
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
  pattern: CompiledPattern,
): Promise<Enumeration | { error: string }> {
  const nonce = randomBytes(8).toString("hex");
  // Chunk encoded rule data as well as the script: brace expansion can exceed
  // cmd.exe's per-variable limit, and patterns must never enter shell source.
  const rules = Buffer.from(
    JSON.stringify({
      directories: pattern.directoryRegexes.map((regex) => regex.source),
      files: pattern.regexes.map((regex) => regex.source),
    }),
  ).toString("base64");
  const chunks = rules.match(/.{1,6000}/g) ?? [];
  const envVars: Record<string, string> = {
    APEX_GLOB_PATH: root,
    APEX_GLOB_CAP: String(MAX_SCAN_ENTRIES),
    APEX_GLOB_NONCE: nonce,
    APEX_GLOB_RULES_COUNT: String(chunks.length),
  };
  for (const [i, chunk] of chunks.entries())
    envVars[`APEX_GLOB_RULES_${i}`] = chunk;
  const result =
    sandbox.type === "windows"
      ? await sandbox.execute(WIN_SCRIPT_COMMAND, {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars: {
            ...winScriptEnv(WIN_GLOB_SCRIPT),
            ...envVars,
          },
        })
      : await sandbox.execute(POSIX_GLOB_COMMAND, {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars,
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
    // Match relative paths with glob separators without changing POSIX filenames.
    entries: lines.map((line) =>
      sandbox.type === "windows"
        ? line.replaceAll("\\", "/")
        : line.startsWith("./")
          ? line.slice(2)
          : line,
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
coverage, venv). Hidden path segments must be explicitly named in the pattern.
Results are capped at ${MAX_RESULTS}; narrow the
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
          ? await enumerateSandbox(ctx.sandbox, root, compiled)
          : await enumerateLocal(root, compiled, ctx.abortSignal);
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
