import { randomBytes } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import type { ListOpts } from "../../../tools/backends/types";
import { resolveFilePath } from "./fileWorkspace";
import type { UnifiedSandbox } from "./sandbox";
import {
  SANDBOX_OP_TIMEOUT_SECONDS,
  sandboxOpError,
  WIN_SCRIPT_COMMAND,
  WIN_SCRIPT_PRELUDE,
  winScriptEnv,
} from "./sandboxScript";
import type { ToolContext } from "./types";

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

export const MAX_RECURSIVE = 200;
export const MAX_NON_RECURSIVE = 500;

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

export async function listFilesImpl(
  ctx: ToolContext,
  directory: string,
  o?: ListOpts,
): Promise<ListFilesResult> {
  const recursive = o?.recursive ?? false;
  let dir: string;
  try {
    dir = await resolveFilePath(ctx, directory ?? ".");
  } catch (err: unknown) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      files: [],
      directory: directory ?? "",
      count: 0,
    };
  }

  try {
    ctx.abortSignal?.throwIfAborted();
    if (ctx.sandbox) {
      const result = await listSandbox(ctx.sandbox, dir, recursive);
      ctx.abortSignal?.throwIfAborted();
      return result;
    }
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
}

// --- Sandbox listings ------------------------------------------------------
//
// A sandboxed agent's directories live inside the sandbox, so listings run
// remotely and never touch the host filesystem. Both backends emit entry
// lines (relative paths, "/" suffix for real directories, symlinks never
// suffixed or descended) then a nonce marker carrying the observed count.
// Entries have the same shape as local Dirents. The nonce keeps a hostile
// entry name from impersonating the marker.

function posixListCommand(): string {
  return [
    "python3 - <<'APEX_LIST_PY'",
    "import os, sys",
    "sys.stdout.reconfigure(encoding='utf-8', errors='surrogateescape')",
    "root = os.environ['APEX_LIST_PATH']",
    "recursive = os.environ['APEX_LIST_RECURSIVE'] == '1'",
    "cap = int(os.environ['APEX_LIST_CAP'])",
    "nonce = os.environ['APEX_LIST_NONCE']",
    "if not os.path.isdir(root): raise NotADirectoryError(root)",
    "total = 0",
    "def walk(directory, prefix=''):",
    "    global total",
    "    with os.scandir(directory) as entries:",
    "        for entry in entries:",
    "            is_directory = entry.is_dir(follow_symlinks=False)",
    "            total += 1",
    "            print(prefix + entry.name + ('/' if is_directory else ''))",
    "            if total >= cap: return",
    "            if recursive and is_directory:",
    "                try: walk(entry.path, prefix + entry.name + '/')",
    "                except OSError: pass",
    "                if total >= cap: return",
    "walk(root)",
    "print(f'APEXLS-{nonce} total={total}')",
    "APEX_LIST_PY",
  ].join("\n");
}

const WIN_LIST_SCRIPT = [
  WIN_SCRIPT_PRELUDE,
  "try{",
  "$p=[Environment]::GetEnvironmentVariable('APEX_LIST_PATH')",
  'if(-not [IO.Directory]::Exists($p)){throw "$p is not a directory"}',
  "$rec=([Environment]::GetEnvironmentVariable('APEX_LIST_RECURSIVE') -eq '1')",
  "$cap=[int64][Environment]::GetEnvironmentVariable('APEX_LIST_CAP')",
  "$nonce=[Environment]::GetEnvironmentVariable('APEX_LIST_NONCE')",
  "$total=[int64]0",
  "$emitted=[int64]0",
  "$baseLen=$p.Length",
  "$stack=New-Object 'System.Collections.Generic.Stack[string]'",
  "$stack.Push($p)",
  "while($stack.Count -gt 0 -and $total -lt $cap){",
  "$d=$stack.Pop()",
  "try{",
  "$di=New-Object IO.DirectoryInfo($d)",
  "foreach($e in $di.EnumerateFileSystemInfos()){",
  "$total++",
  "$isLink=(($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)",
  // FileSystemInfo from the raw .NET enumerator: container detection via
  // Attributes, not the adapted PSIsContainer.
  "$isDir=((($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0) -and -not $isLink)",
  "if($emitted -lt $cap){",
  "$rel=$e.FullName.Substring($baseLen).TrimStart([char]92,[char]47)",
  "if($isDir){[Console]::Out.WriteLine($rel + '/')}else{[Console]::Out.WriteLine($rel)}",
  "$emitted++",
  "}",
  // The cap includes the overflow witness; never schedule its subtree.
  "if($total -ge $cap){break}",
  "if($rec -and $isDir){$stack.Push($e.FullName)}",
  "}",
  "}catch{continue}",
  "}",
  '[Console]::Out.WriteLine("APEXLS-$nonce total=$total")',
  "}catch{",
  "[Console]::Error.WriteLine($_.Exception.Message)",
  "exit 2",
  "}",
].join("\n");

type SandboxListFetch =
  | { ok: true; entries: string[]; total: number }
  | { ok: false; error: string };

function parseSandboxList(stdout: string, nonce: string): SandboxListFetch {
  const lines = stdout.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const marker = lines.pop();
  const match = marker?.match(
    new RegExp(`^APEXLS-${nonce} total=\\s*(\\d+)\\s*$`),
  );
  if (!match) {
    return {
      ok: false,
      error: `sandbox listing missing APEXLS marker: ${stdout.slice(0, 200)}`,
    };
  }
  const entries = lines.map((line) =>
    line.startsWith("./") ? line.slice(2) : line,
  );
  return {
    ok: true,
    entries,
    total: Number.parseInt(match[1], 10),
  };
}

async function listSandbox(
  sandbox: UnifiedSandbox,
  dir: string,
  recursive: boolean,
): Promise<ListFilesResult> {
  const maxEntries = recursive ? MAX_RECURSIVE : MAX_NON_RECURSIVE;
  const nonce = randomBytes(8).toString("hex");
  const envVars = {
    APEX_LIST_PATH: dir,
    APEX_LIST_RECURSIVE: recursive ? "1" : "0",
    APEX_LIST_CAP: String(maxEntries + 1),
    APEX_LIST_NONCE: nonce,
  };
  const result =
    sandbox.type === "windows"
      ? await sandbox.execute(WIN_SCRIPT_COMMAND, {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars: {
            ...winScriptEnv(WIN_LIST_SCRIPT),
            ...envVars,
          },
        })
      : await sandbox.execute(posixListCommand(), {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars,
        });
  if (!result.success || result.exitCode !== 0) {
    return {
      success: false,
      error: sandboxOpError("listing", result),
      files: [],
      directory: dir,
      count: 0,
    };
  }
  const parsed = parseSandboxList(result.stdout, nonce);
  if (!parsed.ok) {
    return {
      success: false,
      error: parsed.error,
      files: [],
      directory: dir,
      count: 0,
    };
  }
  const files = parsed.entries.slice(0, maxEntries);
  const overflow = parsed.total > maxEntries;
  return {
    success: true,
    error: overflow
      ? `Listing truncated at ${maxEntries} entries — narrow the directory or use grep`
      : "",
    files,
    directory: dir,
    count: files.length,
    totalFound: overflow ? parsed.total : undefined,
    totalFoundLowerBound: overflow || undefined,
    truncated: overflow || undefined,
  };
}
