import { createHash } from "node:crypto";
import type { Dirent } from "node:fs";
import { open, readdir, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { throwIfReconAborted } from "./abort";
import type {
  InventoryDirectoryExclusion,
  InventoryFile,
  RepositoryInventory,
} from "./types";

const DEFAULT_MAX_ANALYZABLE_BYTES = 2_000_000;
const SAMPLE_BYTES = 8_192;

const EXCLUDED_DIRECTORIES = new Map<string, string>([
  [".git", "version-control-metadata"],
  [".hg", "version-control-metadata"],
  [".svn", "version-control-metadata"],
  ["node_modules", "third-party-dependencies"],
  ["vendor", "vendored-dependencies"],
  [".venv", "third-party-dependencies"],
  ["venv", "third-party-dependencies"],
  [".terraform", "terraform-provider-cache"],
  ["dist", "generated-build-output"],
  ["build", "generated-build-output"],
  ["coverage", "generated-test-output"],
  [".next", "generated-build-output"],
  [".nuxt", "generated-build-output"],
  [".cache", "generated-cache"],
]);

const BINARY_EXTENSIONS = new Set([
  ".7z",
  ".a",
  ".avi",
  ".bin",
  ".bmp",
  ".class",
  ".dylib",
  ".eot",
  ".exe",
  ".gif",
  ".gz",
  ".ico",
  ".jar",
  ".jpeg",
  ".jpg",
  ".lockb",
  ".mov",
  ".mp3",
  ".mp4",
  ".o",
  ".otf",
  ".pdf",
  ".png",
  ".pyc",
  ".so",
  ".tar",
  ".ttf",
  ".wasm",
  ".webm",
  ".webp",
  ".woff",
  ".woff2",
  ".zip",
]);

const LANGUAGE_BY_EXTENSION = new Map<string, string>([
  [".c", "C"],
  [".cc", "C++"],
  [".cpp", "C++"],
  [".cs", "C#"],
  [".dart", "Dart"],
  [".ex", "Elixir"],
  [".exs", "Elixir"],
  [".go", "Go"],
  [".groovy", "Groovy"],
  [".h", "C/C++"],
  [".java", "Java"],
  [".js", "JavaScript"],
  [".jsx", "JavaScript"],
  [".kt", "Kotlin"],
  [".kts", "Kotlin"],
  [".lua", "Lua"],
  [".php", "PHP"],
  [".pl", "Perl"],
  [".py", "Python"],
  [".rb", "Ruby"],
  [".rs", "Rust"],
  [".scala", "Scala"],
  [".sh", "Shell"],
  [".sql", "SQL"],
  [".swift", "Swift"],
  [".ts", "TypeScript"],
  [".tsx", "TypeScript"],
  [".vue", "Vue"],
]);

const MANIFEST_NAMES = new Set([
  "cargo.toml",
  "composer.json",
  "deno.json",
  "deno.jsonc",
  "gemfile",
  "go.mod",
  "mix.exs",
  "package.json",
  "pnpm-workspace.yaml",
  "pom.xml",
  "pyproject.toml",
  "requirements.txt",
  "settings.gradle",
  "settings.gradle.kts",
  "workspace",
]);

const BUILD_NAMES = new Set([
  "build.gradle",
  "build.gradle.kts",
  "build.sbt",
  "build.xml",
  "makefile",
  "rakefile",
  "turbo.json",
  "vite.config.js",
  "vite.config.ts",
]);

const ENTRYPOINT_NAMES = new Set([
  "app.js",
  "app.py",
  "app.ts",
  "index.js",
  "index.ts",
  "main.go",
  "main.java",
  "main.py",
  "main.rs",
  "main.ts",
  "manage.py",
  "server.js",
  "server.py",
  "server.ts",
]);

const EXCLUDED_FILE_NAMES = new Set([
  ".ds_store",
  "bun.lock",
  "cargo.lock",
  "composer.lock",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "yarn.lock",
]);

export interface InventoryOptions {
  maxAnalyzableBytes?: number;
  abortSignal?: AbortSignal;
}

export async function inventoryRepository(
  repositoryRoot: string,
  options: InventoryOptions = {},
): Promise<RepositoryInventory> {
  const root = await realpath(repositoryRoot);
  const rootStat = await stat(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`White-box recon root is not a directory: ${root}`);
  }

  const files: InventoryFile[] = [];
  const excludedDirectories: InventoryDirectoryExclusion[] = [];
  const maxAnalyzableBytes =
    options.maxAnalyzableBytes ?? DEFAULT_MAX_ANALYZABLE_BYTES;

  async function walk(directory: string): Promise<void> {
    throwIfReconAborted(options.abortSignal);
    let entries: Dirent<string>[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      excludedDirectories.push({
        path: toRepositoryPath(root, directory),
        reason: `unreadable-directory: ${errorMessage(error)}`,
      });
      return;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      throwIfReconAborted(options.abortSignal);
      const absolutePath = path.join(directory, entry.name);
      const relativePath = toRepositoryPath(root, absolutePath);

      if (entry.isDirectory()) {
        const exclusionReason = EXCLUDED_DIRECTORIES.get(entry.name);
        if (exclusionReason) {
          excludedDirectories.push({
            path: relativePath,
            reason: exclusionReason,
          });
        } else {
          await walk(absolutePath);
        }
        continue;
      }

      if (entry.isSymbolicLink()) {
        files.push({
          path: relativePath,
          size_bytes: 0,
          kind: classifyFile(relativePath),
          relevance: "unresolved",
          reason: "symbolic-link-not-followed",
          high_signal: isHighSignal(relativePath),
        });
        continue;
      }

      if (!entry.isFile()) {
        files.push({
          path: relativePath,
          size_bytes: 0,
          kind: classifyFile(relativePath),
          relevance: "unresolved",
          reason: "unsupported-filesystem-entry",
          high_signal: isHighSignal(relativePath),
        });
        continue;
      }
      files.push(
        await inventoryFile(absolutePath, relativePath, maxAnalyzableBytes),
      );
    }
  }

  await walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  excludedDirectories.sort((a, b) => a.path.localeCompare(b.path));

  return {
    repository_root: root,
    files,
    excluded_directories: excludedDirectories,
  };
}

async function inventoryFile(
  absolutePath: string,
  relativePath: string,
  maxAnalyzableBytes: number,
): Promise<InventoryFile> {
  const name = path.basename(relativePath).toLowerCase();
  const extension = path.extname(name);
  const kind = classifyFile(relativePath);
  const language = LANGUAGE_BY_EXTENSION.get(extension);
  const base = {
    path: relativePath,
    kind,
    language,
    high_signal: isHighSignal(relativePath),
  };

  let sizeBytes: number;
  try {
    sizeBytes = (await stat(absolutePath)).size;
  } catch (error) {
    return {
      ...base,
      size_bytes: 0,
      relevance: "unresolved",
      reason: `unreadable-file: ${errorMessage(error)}`,
    };
  }

  if (EXCLUDED_FILE_NAMES.has(name) || name.endsWith(".lock")) {
    return {
      ...base,
      size_bytes: sizeBytes,
      relevance: "excluded",
      reason: "dependency-lockfile",
    };
  }

  if (name.endsWith(".min.js") || name.endsWith(".map")) {
    return {
      ...base,
      size_bytes: sizeBytes,
      relevance: "excluded",
      reason: "generated-source-artifact",
    };
  }

  if (BINARY_EXTENSIONS.has(extension)) {
    return {
      ...base,
      size_bytes: sizeBytes,
      relevance: "excluded",
      reason: "binary-file",
    };
  }

  if (sizeBytes > maxAnalyzableBytes) {
    return {
      ...base,
      size_bytes: sizeBytes,
      relevance: "unresolved",
      reason: `file-exceeds-${maxAnalyzableBytes}-byte-analysis-limit`,
    };
  }

  try {
    const handle = await open(absolutePath, "r");
    try {
      const sample = Buffer.alloc(Math.min(sizeBytes, SAMPLE_BYTES));
      if (sample.length > 0) await handle.read(sample, 0, sample.length, 0);
      if (sample.includes(0)) {
        return {
          ...base,
          size_bytes: sizeBytes,
          relevance: "unresolved",
          reason: "binary-or-unsupported-text-encoding",
        };
      }
    } finally {
      await handle.close();
    }
  } catch (error) {
    return {
      ...base,
      size_bytes: sizeBytes,
      relevance: "unresolved",
      reason: `unreadable-file: ${errorMessage(error)}`,
    };
  }

  try {
    const content = await readFile(absolutePath, "utf8");
    return {
      ...base,
      size_bytes: sizeBytes,
      line_count: content.split("\n").length,
      sha256: createHash("sha256").update(content).digest("hex"),
      relevance: "analyze",
    };
  } catch (error) {
    return {
      ...base,
      size_bytes: sizeBytes,
      relevance: "unresolved",
      reason: `unreadable-file: ${errorMessage(error)}`,
    };
  }
}

function classifyFile(filePath: string): InventoryFile["kind"] {
  const normalized = filePath.toLowerCase();
  const name = path.basename(normalized);
  const extension = path.extname(name);

  if (
    /(^|\/)(?:__tests?__|tests?|testdata|fixtures?)(\/|$)/.test(normalized) ||
    /\.(spec|test)\.[^.]+$/.test(name)
  ) {
    return "test";
  }
  if (
    normalized.startsWith(".buildkite/") ||
    normalized.startsWith(".github/") ||
    normalized.startsWith(".circleci/") ||
    /(?:^|\/)azure-pipelines\.ya?ml$/.test(normalized)
  ) {
    return "build";
  }
  if (
    [
      ".agent-instructions/",
      ".agents/",
      ".claude/",
      ".codex/",
      ".cursor/",
      ".opencode/",
      ".vscode/",
    ].some((prefix) => normalized.startsWith(prefix)) ||
    name === ".mcp.json"
  ) {
    return "documentation";
  }
  if (/^(dockerfile)(\..+)?$/.test(name) || name.includes("compose")) {
    return "container";
  }
  if (
    extension === ".tf" ||
    extension === ".tfvars" ||
    normalized.includes("/pulumi/") ||
    normalized.startsWith("pulumi/") ||
    normalized.includes("/helm/") ||
    normalized.includes("/k8s/") ||
    normalized.includes("/kubernetes/") ||
    name === "serverless.yml" ||
    name === "serverless.yaml" ||
    name === "pulumi.yaml" ||
    name.startsWith("pulumi.")
  ) {
    return "infrastructure";
  }
  if (
    name.includes("openapi") ||
    name.includes("swagger") ||
    extension === ".raml"
  ) {
    return "api-spec";
  }
  if (
    extension === ".proto" ||
    extension === ".graphql" ||
    extension === ".gql"
  ) {
    return "schema";
  }
  if (MANIFEST_NAMES.has(name) || name.startsWith("requirements")) {
    return "manifest";
  }
  if (BUILD_NAMES.has(name) || name.startsWith("webpack.config")) {
    return "build";
  }
  if (LANGUAGE_BY_EXTENSION.has(extension)) return "source";
  if ([".md", ".mdx", ".rst", ".txt"].includes(extension)) {
    return "documentation";
  }
  if (
    name === ".env" ||
    name.startsWith(".env.") ||
    [
      ".conf",
      ".env",
      ".ini",
      ".json",
      ".properties",
      ".toml",
      ".xml",
      ".yaml",
      ".yml",
    ].includes(extension)
  ) {
    return "config";
  }
  return "other";
}

function isHighSignal(filePath: string): boolean {
  const name = path.basename(filePath).toLowerCase();
  const kind = classifyFile(filePath);
  return (
    ENTRYPOINT_NAMES.has(name) ||
    [
      "manifest",
      "build",
      "container",
      "infrastructure",
      "api-spec",
      "schema",
    ].includes(kind)
  );
}

function toRepositoryPath(root: string, absolutePath: string): string {
  const relative = path.relative(root, absolutePath);
  return relative.split(path.sep).join("/") || ".";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
