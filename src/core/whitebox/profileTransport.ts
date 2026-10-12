import { execFile } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import type { CommandBackend } from "../tools/backends/types";
import { runCommandBounded } from "./boundedProcess";
import { DEFAULT_WHITEBOX_EXCLUDED_DIRS } from "./profiles";
import type { ToolAvailability } from "./types";

const execFileAsync = promisify(execFile);
const MAX_PROFILE_FILES = 5_000;
const MAX_PROFILE_OUTPUT_BYTES = 2 * 1024 * 1024;
const WALK_TIMEOUT_SECONDS = 30;
const GIT_TIMEOUT_SECONDS = 5;
const TOOL_DETECT_TIMEOUT_SECONDS = 2;
const TOOL_DETECT_MAX_BYTES = 64 * 1024;

/** `PerCommandShell` substitutes this sentinel for genuinely empty stdout (see `result-registry.ts`'s same strip). */
function stripNoOutputSentinel(stdout: string): string {
  return stdout.replace(/^\(no output\)$/, "");
}

/** `cd`'d into `rootPath` and asserts it exists and is a directory — mirrors `stat(rootPath).isDirectory()`. */
async function assertDirectory(
  rootPath: string,
  command: CommandBackend | undefined,
): Promise<void> {
  const result = await runCommandBounded(command, ["test", "-d", "."], {
    cwd: rootPath,
    timeoutSeconds: GIT_TIMEOUT_SECONDS,
    maxTotalBytes: 1_024,
  });
  if (result.exitCode !== 0) {
    throw new Error(`${rootPath} is not a directory`);
  }
}

/**
 * Prunes excluded dirs at any depth and lists files only — symlinks match
 * neither `-type d` nor `-type f`, so they're skipped, same as the old
 * `Dirent`-based walk (a `Dirent` for a symlink is neither). Sorted in the C
 * locale to match Node's `readdir()` order (libuv sorts entries), which the
 * old recursive walk relied on implicitly.
 */
function buildFindCommand(): string {
  const prune = DEFAULT_WHITEBOX_EXCLUDED_DIRS.map(
    (dir) => `-name '${dir}'`,
  ).join(" -o ");
  return `find . -mindepth 1 \\( -type d \\( ${prune} \\) -prune \\) -o -type f -print | LC_ALL=C sort`;
}

function shouldSkipDir(name: string): boolean {
  return DEFAULT_WHITEBOX_EXCLUDED_DIRS.includes(name);
}

async function walkFiles(
  rootPath: string,
  command?: CommandBackend,
): Promise<string[]> {
  if (command) {
    const result = await runCommandBounded(
      command,
      ["bash", "-c", buildFindCommand()],
      {
        cwd: rootPath,
        timeoutSeconds: WALK_TIMEOUT_SECONDS,
        maxTotalBytes: MAX_PROFILE_OUTPUT_BYTES,
      },
    );
    const stdout = stripNoOutputSentinel(result.stdout);
    if (!stdout) return [];
    return stdout
      .split("\n")
      .filter(Boolean)
      .map((line) => line.replace(/^\.\//, ""))
      .slice(0, MAX_PROFILE_FILES);
  }
  const files: string[] = [];
  const absRoot = resolve(rootPath);

  function isWithinRoot(path: string): boolean {
    try {
      const real = realpathSync(path);
      return real === absRoot || real.startsWith(`${absRoot}/`);
    } catch {
      return false;
    }
  }

  async function walk(current: string): Promise<void> {
    if (files.length >= MAX_PROFILE_FILES) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= MAX_PROFILE_FILES) return;
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (shouldSkipDir(entry.name)) continue;
        if (entry.isSymbolicLink() && !isWithinRoot(fullPath)) continue;
        await walk(fullPath);
        continue;
      }
      if (entry.isFile()) {
        files.push(relative(rootPath, fullPath));
      }
    }
  }

  await walk(rootPath);
  return files;
}

async function readPackageJson(
  rootPath: string,
  command?: CommandBackend,
): Promise<string | undefined> {
  let raw: string;
  if (command) {
    const result = await runCommandBounded(command, ["cat", "package.json"], {
      cwd: rootPath,
      timeoutSeconds: GIT_TIMEOUT_SECONDS,
      maxTotalBytes: MAX_PROFILE_OUTPUT_BYTES,
    });
    raw = stripNoOutputSentinel(result.stdout);
    if (result.exitCode !== 0 || !raw.trim()) {
      return undefined;
    }
  } else {
    const packageJsonPath = join(rootPath, "package.json");
    if (!existsSync(packageJsonPath)) {
      return undefined;
    }
    try {
      raw = await readFile(packageJsonPath, "utf-8");
    } catch {
      return undefined;
    }
  }

  return raw;
}

async function runGit(
  rootPath: string,
  args: string[],
  command?: CommandBackend,
): Promise<string | undefined> {
  if (command) {
    const result = await runCommandBounded(command, ["git", ...args], {
      cwd: rootPath,
      timeoutSeconds: GIT_TIMEOUT_SECONDS,
      maxTotalBytes: MAX_PROFILE_OUTPUT_BYTES,
    });
    return result.exitCode === 0
      ? stripNoOutputSentinel(result.stdout).trim()
      : undefined;
  }
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd: rootPath,
      timeout: 5_000,
      maxBuffer: 1024 * 1024,
    });
    return String(stdout).trim();
  } catch {
    return undefined;
  }
}

async function detectTool(
  name: string,
  rootPath: string,
  command?: CommandBackend,
): Promise<ToolAvailability> {
  if (command) {
    const result = await runCommandBounded(command, ["which", name], {
      cwd: rootPath,
      timeoutSeconds: TOOL_DETECT_TIMEOUT_SECONDS,
      maxTotalBytes: TOOL_DETECT_MAX_BYTES,
    });
    const path = stripNoOutputSentinel(result.stdout).trim();
    return result.exitCode === 0 && path
      ? { name, available: true, path }
      : { name, available: false };
  }
  const cmd = process.platform === "win32" ? "where" : "which";
  try {
    const { stdout } = await execFileAsync(cmd, [name], {
      timeout: 2_000,
      maxBuffer: 1024 * 64,
    });
    return { name, available: true, path: String(stdout).trim() };
  } catch {
    return { name, available: false };
  }
}

export interface RepoProfileIO {
  assertDirectory(rootPath: string): Promise<void>;
  walkFiles(rootPath: string): Promise<string[]>;
  readPackageJson(rootPath: string): Promise<string | undefined>;
  runGit(rootPath: string, args: string[]): Promise<string | undefined>;
  detectTool(name: string, rootPath: string): Promise<ToolAvailability>;
}

export function createRepoProfileIO(command?: CommandBackend): RepoProfileIO {
  return {
    async assertDirectory(rootPath) {
      if (command) return assertDirectory(rootPath, command);
      const rootStat = await stat(rootPath);
      if (!rootStat.isDirectory())
        throw new Error(`${rootPath} is not a directory`);
    },
    walkFiles: (rootPath) => walkFiles(rootPath, command),
    readPackageJson: (rootPath) => readPackageJson(rootPath, command),
    runGit: (rootPath, args) => runGit(rootPath, args, command),
    detectTool: (name, rootPath) => detectTool(name, rootPath, command),
  };
}
