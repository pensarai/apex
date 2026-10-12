import { basename, extname } from "node:path";
import type { CommandBackend } from "../tools/backends/types";
import { DEFAULT_WHITEBOX_EXCLUDED_DIRS } from "./profiles";
import { createRepoProfileIO, type RepoProfileIO } from "./profileTransport";
import type { LanguageId, PackageManagerId, RepoProfile } from "./types";

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

async function readPackageScripts(
  rootPath: string,
  io: RepoProfileIO,
): Promise<{
  buildCommands: string[];
  testCommands: string[];
  runCommands: string[];
}> {
  const raw = await io.readPackageJson(rootPath);
  if (!raw) return { buildCommands: [], testCommands: [], runCommands: [] };

  try {
    const parsed = JSON.parse(raw) as {
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

export async function profileCodebase(
  rootPath: string,
  command?: CommandBackend | RepoProfileIO,
): Promise<RepoProfile> {
  const io =
    command && "walkFiles" in command ? command : createRepoProfileIO(command);
  await io.assertDirectory(rootPath);

  const files = await io.walkFiles(rootPath);
  const packageScripts = await readPackageScripts(rootPath, io);
  const currentCommit = await io.runGit(rootPath, ["rev-parse", "HEAD"]);
  const submodulesRaw = await io.runGit(rootPath, ["submodule", "status"]);
  const submodules = submodulesRaw
    ? submodulesRaw
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
    : [];

  const languages = detectLanguages(files);
  const packageManagers = detectPackageManagers(files);
  const toolAvailability = await Promise.all(
    TOOL_NAMES.map((name) => io.detectTool(name, rootPath)),
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
