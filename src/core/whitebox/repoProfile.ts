import { execFile } from "child_process";
import { existsSync } from "fs";
import { readdir, readFile, stat } from "fs/promises";
import { basename, extname, join, relative } from "path";
import { promisify } from "util";
import { DEFAULT_WHITEBOX_EXCLUDED_DIRS } from "./profiles";
import type {
  LanguageId,
  PackageManagerId,
  RepoProfile,
  ToolAvailability,
} from "./types";

const execFileAsync = promisify(execFile);
const MAX_PROFILE_FILES = 5_000;

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
  "*.csproj": ["dotnet"],
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
  "pip-audit",
  "govulncheck",
  "brakeman",
  "spotbugs",
  "jazzer",
];

function shouldSkipDir(name: string): boolean {
  return DEFAULT_WHITEBOX_EXCLUDED_DIRS.includes(name);
}

async function walkFiles(rootPath: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(current: string): Promise<void> {
    if (files.length >= MAX_PROFILE_FILES) return;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= MAX_PROFILE_FILES) return;
      if (entry.isDirectory()) {
        if (!shouldSkipDir(entry.name)) {
          await walk(join(current, entry.name));
        }
        continue;
      }
      if (entry.isFile()) {
        files.push(relative(rootPath, join(current, entry.name)));
      }
    }
  }

  await walk(rootPath);
  return files;
}

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

async function readPackageScripts(rootPath: string): Promise<{
  buildCommands: string[];
  testCommands: string[];
  runCommands: string[];
}> {
  const packageJsonPath = join(rootPath, "package.json");
  if (!existsSync(packageJsonPath)) {
    return { buildCommands: [], testCommands: [], runCommands: [] };
  }

  try {
    const parsed = JSON.parse(await readFile(packageJsonPath, "utf-8")) as {
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
    return { buildCommands: [], testCommands: [], runCommands: [] };
  }
}

async function runGit(
  rootPath: string,
  args: string[],
): Promise<string | undefined> {
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

async function detectTool(name: string): Promise<ToolAvailability> {
  try {
    const { stdout } = await execFileAsync("which", [name], {
      timeout: 2_000,
      maxBuffer: 1024 * 64,
    });
    return { name, available: true, path: String(stdout).trim() };
  } catch {
    return { name, available: false };
  }
}

export async function profileCodebase(rootPath: string): Promise<RepoProfile> {
  const rootStat = await stat(rootPath);
  if (!rootStat.isDirectory()) {
    throw new Error(`${rootPath} is not a directory`);
  }

  const files = await walkFiles(rootPath);
  const packageScripts = await readPackageScripts(rootPath);
  const currentCommit = await runGit(rootPath, ["rev-parse", "HEAD"]);
  const submodulesRaw = await runGit(rootPath, ["submodule", "status"]);
  const submodules = submodulesRaw
    ? submodulesRaw
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
    : [];

  const languages = detectLanguages(files);
  const packageManagers = detectPackageManagers(files);
  const toolAvailability = await Promise.all(TOOL_NAMES.map(detectTool));

  return {
    rootPath,
    currentCommit,
    languages,
    packageManagers,
    manifestFiles: detectManifestFiles(files),
    lockfiles: files.filter((file) => basename(file).includes("lock")),
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
