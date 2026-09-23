import { basename, extname } from "node:path";
import type { CommandBackend } from "../tools/backends/types";
import { runCommandBounded } from "./boundedProcess";
import { DEFAULT_WHITEBOX_EXCLUDED_DIRS } from "./profiles";
import type {
  LanguageId,
  PackageManagerId,
  RepoProfile,
  ToolAvailability,
} from "./types";

const MAX_PROFILE_FILES = 5_000;
const MAX_PROFILE_OUTPUT_BYTES = 2 * 1024 * 1024;
const WALK_TIMEOUT_SECONDS = 30;
const GIT_TIMEOUT_SECONDS = 5;
const TOOL_DETECT_TIMEOUT_SECONDS = 2;
const TOOL_DETECT_MAX_BYTES = 64 * 1024;

const LANGUAGE_BY_EXTENSION: Record<string, LanguageId> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".rb": "ruby",
  ".php": "php",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".cxx": "cpp",
  ".hpp": "cpp",
  ".cs": "csharp",
};

const LOCKFILE_BASENAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "poetry.lock",
  "Pipfile.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "composer.lock",
  "go.sum",
  "flake.lock",
]);

const MANIFEST_PACKAGE_MANAGERS: Record<string, PackageManagerId[]> = {
  "bun.lock": ["bun"],
  "bun.lockb": ["bun"],
  "package.json": ["npm"],
  "package-lock.json": ["npm"],
  "yarn.lock": ["yarn"],
  "pnpm-lock.yaml": ["pnpm"],
  "requirements.txt": ["pip"],
  "pyproject.toml": ["poetry"],
  "Cargo.toml": ["cargo"],
  "go.mod": ["go"],
  "pom.xml": ["maven"],
  "build.gradle": ["gradle"],
  "build.gradle.kts": ["gradle"],
  Gemfile: ["bundler"],
  "composer.json": ["composer"],
};

const TOOL_NAMES = [
  "tokei",
  "rg",
  "ast-grep",
  "comby",
  "semgrep",
  "codeql",
  "bandit",
  "gosec",
  "cargo-geiger",
  "cargo-audit",
  "gitleaks",
  "trufflehog",
  "noseyparker",
  "osv-scanner",
  "trivy",
  "grype",
  "npm",
  "pip-audit",
  "govulncheck",
  "brakeman",
  "spotbugs",
  "jazzer",
];

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function detectLanguages(files: string[]): LanguageId[] {
  const languages = files
    .map((file) => LANGUAGE_BY_EXTENSION[extname(file)])
    .filter((language): language is LanguageId => Boolean(language));
  return unique(languages.length > 0 ? languages : ["unknown"]);
}

function detectManifestFiles(files: string[]): string[] {
  return files.filter((file) => {
    const name = basename(file);
    return (
      Object.hasOwn(MANIFEST_PACKAGE_MANAGERS, name) ||
      name.endsWith(".csproj") ||
      name === "Dockerfile" ||
      name === "docker-compose.yml" ||
      name === "docker-compose.yaml"
    );
  });
}

function detectPackageManagers(files: string[]): PackageManagerId[] {
  const managers: PackageManagerId[] = [];
  for (const file of files) {
    const name = basename(file);
    if (name.endsWith(".csproj")) {
      managers.push("dotnet");
      continue;
    }
    managers.push(...(MANIFEST_PACKAGE_MANAGERS[name] ?? []));
  }
  return unique(managers);
}

function detectIaC(files: string[]): string[] {
  return files.filter((file) => {
    const lower = file.toLowerCase();
    return (
      lower.endsWith(".tf") ||
      lower.includes("cloudformation") ||
      lower.includes("serverless.yml") ||
      lower.includes("serverless.yaml") ||
      lower.includes("sst.config") ||
      lower.includes("pulumi") ||
      lower.includes("cdk") ||
      lower.includes("kubernetes") ||
      lower.includes("/k8s/") ||
      lower.includes("/helm/")
    );
  });
}

function detectCi(files: string[]): string[] {
  return files.filter((file) => {
    const lower = file.toLowerCase();
    return (
      lower.startsWith(".github/workflows/") ||
      lower.includes(".gitlab-ci") ||
      lower.includes("circleci") ||
      lower.includes("buildkite") ||
      lower.includes("jenkinsfile")
    );
  });
}

function detectEntryHints(files: string[]): string[] {
  const hints = files.filter((file) => {
    const lower = file.toLowerCase();
    return (
      lower.includes("route") ||
      lower.includes("controller") ||
      lower.includes("handler") ||
      lower.includes("server") ||
      lower.includes("webhook") ||
      lower.includes("lambda") ||
      lower.includes("schema.graphql") ||
      lower.endsWith(".proto")
    );
  });
  return hints.slice(0, 100);
}

/** `PersistentShell` substitutes this sentinel for genuinely empty stdout (see `result-registry.ts`'s same strip). */
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

async function walkFiles(
  rootPath: string,
  command: CommandBackend | undefined,
): Promise<string[]> {
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

async function readPackageScripts(
  rootPath: string,
  command: CommandBackend | undefined,
): Promise<{
  buildCommands: string[];
  testCommands: string[];
  runCommands: string[];
}> {
  const empty = { buildCommands: [], testCommands: [], runCommands: [] };
  const result = await runCommandBounded(command, ["cat", "package.json"], {
    cwd: rootPath,
    timeoutSeconds: GIT_TIMEOUT_SECONDS,
    maxTotalBytes: MAX_PROFILE_OUTPUT_BYTES,
  });
  const stdout = stripNoOutputSentinel(result.stdout);
  if (result.exitCode !== 0 || !stdout.trim()) return empty;

  try {
    const parsed = JSON.parse(stdout) as {
      scripts?: Record<string, string>;
      packageManager?: string;
    };
    const scripts = parsed.scripts ?? {};
    const runner = parsed.packageManager?.startsWith("bun")
      ? "bun run"
      : "npm run";
    return {
      buildCommands: Object.keys(scripts)
        .filter((name) => name.includes("build"))
        .map((name) => `${runner} ${name}`),
      testCommands: Object.keys(scripts)
        .filter((name) => name.includes("test"))
        .map((name) => `${runner} ${name}`),
      runCommands: Object.keys(scripts)
        .filter((name) => ["dev", "start"].includes(name))
        .map((name) => `${runner} ${name}`),
    };
  } catch {
    return empty;
  }
}

async function gitInfo(
  rootPath: string,
  args: string[],
  command: CommandBackend | undefined,
): Promise<string | undefined> {
  const result = await runCommandBounded(command, ["git", ...args], {
    cwd: rootPath,
    timeoutSeconds: GIT_TIMEOUT_SECONDS,
    maxTotalBytes: MAX_PROFILE_OUTPUT_BYTES,
  });
  return result.exitCode === 0
    ? stripNoOutputSentinel(result.stdout).trim()
    : undefined;
}

async function detectTool(
  name: string,
  rootPath: string,
  command: CommandBackend | undefined,
): Promise<ToolAvailability> {
  const which = process.platform === "win32" ? "where" : "which";
  const result = await runCommandBounded(command, [which, name], {
    cwd: rootPath,
    timeoutSeconds: TOOL_DETECT_TIMEOUT_SECONDS,
    maxTotalBytes: TOOL_DETECT_MAX_BYTES,
  });
  const path = stripNoOutputSentinel(result.stdout).trim();
  if (result.exitCode === 0 && path) {
    return { name, available: true, path };
  }
  return { name, available: false };
}

/**
 * Profile a repository through the resolved {@link CommandBackend} — no
 * direct `node:fs` / `node:child_process` access, so this works identically
 * whether `rootPath` is on the local host or inside a remote sandbox.
 */
export async function profileCodebase(
  rootPath: string,
  command: CommandBackend | undefined,
): Promise<RepoProfile> {
  await assertDirectory(rootPath, command);

  const files = await walkFiles(rootPath, command);
  const packageScripts = await readPackageScripts(rootPath, command);
  const currentCommit = await gitInfo(rootPath, ["rev-parse", "HEAD"], command);
  const submodulesRaw = await gitInfo(
    rootPath,
    ["submodule", "status"],
    command,
  );
  const submodules = submodulesRaw
    ? submodulesRaw
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
    : [];

  const languages = detectLanguages(files);
  const packageManagers = detectPackageManagers(files);
  const toolAvailability = await Promise.all(
    TOOL_NAMES.map((name) => detectTool(name, rootPath, command)),
  );

  return {
    rootPath,
    currentCommit,
    languages,
    packageManagers,
    manifestFiles: detectManifestFiles(files),
    lockfiles: files.filter((file) => LOCKFILE_BASENAMES.has(basename(file))),
    buildCommands: packageScripts.buildCommands,
    testCommands: packageScripts.testCommands,
    runCommands: packageScripts.runCommands,
    entryPointHints: detectEntryHints(files),
    iacFiles: detectIaC(files),
    ciFiles: detectCi(files),
    nativeCode: languages.some((language) =>
      ["c", "cpp", "rust"].includes(language),
    ),
    submodules,
    excludedDirs: DEFAULT_WHITEBOX_EXCLUDED_DIRS,
    toolAvailability,
  };
}
