#!/usr/bin/env bun
import { execSync } from "node:child_process";
import type { Dirent } from "node:fs";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";

interface RepoProfile {
  path: string;
  languages: string[];
  packageManagers: string[];
  lockfiles: string[];
  build: string;
  test: string;
  installedScanners: string[];
  entryPoints: string[];
  git: { sha: string; branch: string; remote: string };
}

interface ProfileError {
  error: string;
  path?: string;
}

const EXCLUDED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "target",
  "vendor",
]);

const EXT_TO_LANG: Record<string, string> = {
  ".py": "python",
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".kt": "kotlin",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".swift": "swift",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".cc": "cpp",
  ".hpp": "cpp",
};

const ENTRY_POINT_HINTS = [
  "src/index.ts",
  "src/main.ts",
  "src/cli.ts",
  "src/app.ts",
  "src/server.ts",
  "src/index.js",
  "src/main.js",
  "src/cli.js",
  "src/app.js",
  "src/server.js",
  "main.py",
  "app.py",
  "manage.py",
  "wsgi.py",
  "asgi.py",
  "main.go",
  "cmd/main.go",
  "src/main.rs",
  "src/lib.rs",
  "main.rb",
  "app.rb",
  "config.ru",
  "index.php",
];

const KNOWN_SCANNERS = [
  "semgrep",
  "gitleaks",
  "osv-scanner",
  "trivy",
  "bandit",
  "gosec",
  "cargo-audit",
  "pip-audit",
  "npm",
  "trufflehog",
];

/** Single directory walk that detects every supported language. */
function detectLanguages(root: string, depthLimit = 6): string[] {
  const found = new Set<string>();
  const targets = new Set(Object.keys(EXT_TO_LANG));

  function walk(dir: string, depth: number): void {
    if (depth > depthLimit) return;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true }) as Dirent[];
    } catch {
      return;
    }
    for (const entry of entries) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      if (entry.isDirectory()) {
        walk(join(dir, entry.name), depth + 1);
        continue;
      }
      if (entry.isFile()) {
        const ext = extname(entry.name);
        if (targets.has(ext)) {
          const lang = EXT_TO_LANG[ext];
          if (lang) found.add(lang);
        }
      }
    }
    // Early exit when we've found all the languages we care about.
    if (found.size >= new Set(Object.values(EXT_TO_LANG)).size) {
      throw new EarlyExit();
    }
  }

  class EarlyExit extends Error {}
  try {
    walk(root, 0);
  } catch (e) {
    if (!(e instanceof EarlyExit)) throw e;
  }
  return [...found];
}

function detectPackageManagers(root: string): {
  managers: string[];
  lockfiles: string[];
} {
  const managers: string[] = [];
  const lockfiles: string[] = [];
  const has = (f: string) => existsSync(join(root, f));

  if (has("package.json")) {
    if (has("bun.lock") || has("bun.lockb")) {
      managers.push("bun");
      lockfiles.push("bun.lock");
    } else if (has("pnpm-lock.yaml")) {
      managers.push("pnpm");
      lockfiles.push("pnpm-lock.yaml");
    } else if (has("yarn.lock")) {
      managers.push("yarn");
      lockfiles.push("yarn.lock");
    } else if (has("package-lock.json")) {
      managers.push("npm");
      lockfiles.push("package-lock.json");
    } else {
      managers.push("npm");
    }
  }
  if (has("Cargo.toml")) managers.push("cargo");
  if (has("Cargo.lock")) lockfiles.push("Cargo.lock");
  if (has("go.mod")) managers.push("go-modules");
  if (has("go.sum")) lockfiles.push("go.sum");
  if (has("pyproject.toml")) managers.push("python/pyproject");
  if (has("requirements.txt")) {
    managers.push("pip");
    lockfiles.push("requirements.txt");
  }
  if (has("Pipfile")) managers.push("pipenv");
  if (has("Pipfile.lock")) lockfiles.push("Pipfile.lock");
  if (has("poetry.lock")) lockfiles.push("poetry.lock");
  if (has("Gemfile")) managers.push("bundler");
  if (has("Gemfile.lock")) lockfiles.push("Gemfile.lock");
  if (has("composer.json")) managers.push("composer");
  if (has("composer.lock")) lockfiles.push("composer.lock");
  if (has("pom.xml")) managers.push("maven");
  if (has("build.gradle") || has("build.gradle.kts")) managers.push("gradle");

  return { managers, lockfiles };
}

function detectBuildAndTest(root: string): { build: string; test: string } {
  const pkg = join(root, "package.json");
  if (!existsSync(pkg)) return { build: "", test: "" };
  try {
    const data = JSON.parse(readFileSync(pkg, "utf-8"));
    const scripts = (data?.scripts ?? {}) as Record<string, string>;
    return { build: scripts.build ?? "", test: scripts.test ?? "" };
  } catch {
    return { build: "", test: "" };
  }
}

function isOnPath(bin: string): boolean {
  try {
    execSync(`command -v ${bin}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function detectScanners(): string[] {
  return KNOWN_SCANNERS.filter(isOnPath);
}

function detectEntryPoints(root: string): string[] {
  return ENTRY_POINT_HINTS.filter((p) => existsSync(join(root, p)));
}

function readGitMetadata(root: string): RepoProfile["git"] {
  if (!existsSync(join(root, ".git"))) {
    return { sha: "", branch: "", remote: "" };
  }
  const run = (cmd: string): string => {
    try {
      return execSync(cmd, { cwd: root, stdio: ["ignore", "pipe", "ignore"] })
        .toString()
        .trim();
    } catch {
      return "";
    }
  };
  return {
    sha: run("git rev-parse HEAD"),
    branch: run("git rev-parse --abbrev-ref HEAD"),
    remote: run("git config --get remote.origin.url"),
  };
}

export function profileRepo(codebasePath: string): RepoProfile | ProfileError {
  if (!existsSync(codebasePath)) {
    return { error: "codebase path does not exist", path: codebasePath };
  }
  if (!statSync(codebasePath).isDirectory()) {
    return { error: "codebase path is not a directory", path: codebasePath };
  }
  const { managers, lockfiles } = detectPackageManagers(codebasePath);
  const { build, test } = detectBuildAndTest(codebasePath);
  return {
    path: codebasePath,
    languages: detectLanguages(codebasePath),
    packageManagers: managers,
    lockfiles,
    build,
    test,
    installedScanners: detectScanners(),
    entryPoints: detectEntryPoints(codebasePath),
    git: readGitMetadata(codebasePath),
  };
}

function isCli(): boolean {
  const entry = process.argv[1] ?? "";
  return /profile\.(ts|js)$/.test(entry);
}

if (isCli()) {
  const codebase = process.argv[2];
  if (!codebase) {
    process.stderr.write("Usage: bun profile.ts <codebase_path>\n");
    process.exit(2);
  }
  const result = profileRepo(codebase);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
