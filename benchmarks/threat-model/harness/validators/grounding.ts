/**
 * Threat Model Benchmark — Grounding Validator
 *
 * Cross-checks claims in the threat model output against
 * the actual source tree. No LLM calls.
 */

import { existsSync } from "fs";
import { resolve, extname } from "path";
import { spawnSync } from "child_process";
import type { ParsedThreatModel, GroundingScore } from "../types";

// ---------------------------------------------------------------------------
// Extraction Helpers
// ---------------------------------------------------------------------------

const SOURCE_EXTS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs", ".php",
  ".java", ".rb", ".vue", ".svelte", ".c", ".cpp", ".h", ".cs",
  ".swift", ".kt", ".yaml", ".yml", ".json", ".toml",
]);

const CONFIG_NAMES = new Set([
  "dockerfile", "docker-compose.yml", "docker-compose.yaml",
  ".env", ".env.example", ".env.local", ".env.production",
  "package.json", "tsconfig.json", "go.mod", "go.sum", "cargo.toml",
  "pyproject.toml", "requirements.txt", "gemfile",
  ".github/workflows", "jenkinsfile", ".gitlab-ci.yml",
  "serverless.yml", "template.yaml", "template.yml",
  "terraform", "kubernetes", "k8s",
]);

/** Extract file-path-like strings from markdown text */
function extractFilePaths(md: string): string[] {
  const paths = new Set<string>();

  // Match inline code references: `src/routes/auth.ts`
  const codeRe = /`([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})`/g;
  let m: RegExpExecArray | null;
  while ((m = codeRe.exec(md)) !== null) {
    const p = m[1];
    if (p.includes("/") || SOURCE_EXTS.has(extname(p).toLowerCase())) {
      paths.add(p);
    }
  }

  // Match bare file paths in text (with directory separator)
  const bareRe =
    /(?:^|[\s,|])([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})(?=[\s,|)\]`]|$)/gm;
  while ((m = bareRe.exec(md)) !== null) {
    paths.add(m[1]);
  }

  return [...paths];
}

/** Extract HTTP endpoint references */
function extractEndpoints(md: string): string[] {
  const eps = new Set<string>();
  const re =
    /(?:GET|POST|PUT|DELETE|PATCH)\s+(\/[a-zA-Z0-9/:{}_\-.*]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(md)) !== null) {
    // Strip trailing punctuation
    eps.add(m[1].replace(/[.,;)]+$/, ""));
  }
  return [...eps];
}

/** Extract middleware/package names from security controls text */
function extractPackageNames(parsed: ParsedThreatModel): string[] {
  const names = new Set<string>();
  for (const sc of parsed.securityControls) {
    // Look for known patterns
    const text = `${sc.name} ${sc.implementation}`;
    const packageRe =
      /\b(helmet|cors|express-rate-limit|bcrypt|jsonwebtoken|passport|csrf|zod|joi|validator|sanitize|prisma|sequelize|mongoose|django|flask|gin|actix|axum)\b/gi;
    let m: RegExpExecArray | null;
    while ((m = packageRe.exec(text)) !== null) {
      names.add(m[1].toLowerCase());
    }
  }
  return [...names];
}

// ---------------------------------------------------------------------------
// Verification Helpers
// ---------------------------------------------------------------------------

function fileExists(codebasePath: string, ref: string): boolean {
  // Try resolving relative to codebase root (src/)
  if (existsSync(resolve(codebasePath, ref))) return true;
  // Try one level up (some refs are relative to repo root, not src/)
  if (existsSync(resolve(codebasePath, "..", ref))) return true;
  // Try the ref as-is (might already be absolute-ish)
  if (existsSync(resolve(codebasePath, ref.replace(/^\//, "")))) return true;
  return false;
}

function grepExists(codebasePath: string, pattern: string): boolean {
  const result = spawnSync(
    "grep",
    ["-rl", "--include=*.ts", "--include=*.py", "--include=*.go",
     "--include=*.rs", "--include=*.php", "--include=*.java",
     "--include=*.rb", "--include=*.js", "--include=*.yaml",
     "--include=*.yml", "--include=*.json", "--include=*.toml",
     pattern, codebasePath],
    { timeout: 5000, encoding: "utf-8" },
  );
  return (result.stdout ?? "").trim().length > 0;
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

function checkFilePaths(
  parsed: ParsedThreatModel,
  codebasePath: string,
): { score: number; found: number; total: number } {
  const refs = extractFilePaths(parsed.raw);
  if (refs.length === 0) return { score: 0, found: 0, total: 0 };

  let found = 0;
  for (const ref of refs) {
    if (fileExists(codebasePath, ref)) found++;
  }
  return { score: found / refs.length, found, total: refs.length };
}

function checkEndpoints(
  parsed: ParsedThreatModel,
  codebasePath: string,
): { score: number; found: number; total: number } {
  const eps = extractEndpoints(parsed.raw);
  if (eps.length === 0) return { score: 0, found: 0, total: 0 };

  let found = 0;
  for (const ep of eps) {
    // Extract path segment (strip params like :id, {id})
    const pathSegment = ep
      .replace(/:[a-zA-Z_]+/g, "")
      .replace(/\{[a-zA-Z_]+}/g, "")
      .replace(/\/+/g, "/")
      .replace(/\/$/, "");

    // Grep for the literal path or significant segments
    const segments = pathSegment.split("/").filter((s) => s.length > 2);
    const searchTerm = segments.length > 0 ? segments[segments.length - 1] : pathSegment;
    if (searchTerm && grepExists(codebasePath, searchTerm)) found++;
  }
  return { score: found / eps.length, found, total: eps.length };
}

function checkPackages(
  parsed: ParsedThreatModel,
  codebasePath: string,
): { score: number; found: number; total: number } {
  const packages = extractPackageNames(parsed);
  if (packages.length === 0) return { score: 0, found: 0, total: 0 };

  let found = 0;
  for (const pkg of packages) {
    if (grepExists(codebasePath, pkg)) found++;
  }
  return { score: found / packages.length, found, total: packages.length };
}

function checkConfigFiles(
  parsed: ParsedThreatModel,
  codebasePath: string,
): { score: number; found: number; total: number } {
  const refs = extractFilePaths(parsed.raw).filter((r) => {
    const lower = r.toLowerCase();
    return (
      CONFIG_NAMES.has(lower) ||
      lower.includes("dockerfile") ||
      lower.includes("docker-compose") ||
      lower.includes(".env") ||
      lower.includes("package.json") ||
      lower.includes("go.mod") ||
      lower.includes("cargo.toml") ||
      lower.endsWith(".yml") ||
      lower.endsWith(".yaml")
    );
  });

  if (refs.length === 0) return { score: 0, found: 0, total: 0 };

  let found = 0;
  for (const ref of refs) {
    if (fileExists(codebasePath, ref)) found++;
  }
  return { score: found / refs.length, found, total: refs.length };
}

function checkAttackPathEntryPoints(
  parsed: ParsedThreatModel,
  codebasePath: string,
): { score: number; found: number; total: number } {
  if (parsed.attackPaths.length === 0)
    return { score: 0, found: 0, total: 0 };

  let found = 0;
  let total = 0;
  for (const ap of parsed.attackPaths) {
    if (!ap.entryPoint) continue;
    total++;

    // Check if entry point references an endpoint or file
    const epMatch = ap.entryPoint.match(
      /(?:GET|POST|PUT|DELETE|PATCH)\s+(\/[^\s,]+)/i,
    );
    if (epMatch) {
      const segments = epMatch[1]
        .replace(/:[a-zA-Z_]+/g, "")
        .replace(/\{[a-zA-Z_]+}/g, "")
        .split("/")
        .filter((s) => s.length > 2);
      const searchTerm = segments[segments.length - 1];
      if (searchTerm && grepExists(codebasePath, searchTerm)) {
        found++;
        continue;
      }
    }

    // Check for file path reference
    const fileMatch = ap.entryPoint.match(
      /([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})/,
    );
    if (fileMatch && fileExists(codebasePath, fileMatch[1])) {
      found++;
      continue;
    }

    // Check for CLI flag or generic feature name (just grep for keywords)
    const keywords = ap.entryPoint
      .replace(/[^a-zA-Z0-9]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 3);
    if (keywords.some((kw) => grepExists(codebasePath, kw))) {
      found++;
    }
  }

  return {
    score: total > 0 ? found / total : 0,
    found,
    total,
  };
}

// ---------------------------------------------------------------------------
// Main Validator
// ---------------------------------------------------------------------------

export function validateGrounding(
  parsed: ParsedThreatModel,
  codebasePath: string,
): GroundingScore {
  const files = checkFilePaths(parsed, codebasePath);
  const endpoints = checkEndpoints(parsed, codebasePath);
  const packages = checkPackages(parsed, codebasePath);
  const config = checkConfigFiles(parsed, codebasePath);
  const entryPoints = checkAttackPathEntryPoints(parsed, codebasePath);

  const checks = {
    files_exist: files,
    endpoints_exist: endpoints,
    packages_exist: packages,
    config_files_exist: config,
    entry_points_verified: entryPoints,
  };

  // Weighted average: files 25%, endpoints 25%, entry points 25%, packages 15%, config 10%
  const weights = {
    files_exist: 0.25,
    endpoints_exist: 0.25,
    entry_points_verified: 0.25,
    packages_exist: 0.15,
    config_files_exist: 0.10,
  };

  let score = 0;
  for (const [key, weight] of Object.entries(weights)) {
    score += (checks[key as keyof typeof checks]?.score ?? 0) * weight;
  }

  return { score, checks };
}
