import { existsSync, realpathSync } from "node:fs";
import { isAbsolute, normalize, relative, resolve } from "node:path";

/**
 * Repository root used for whitebox profiling, scans, and code queries.
 * Prefer explicit `session.config.codebasePath` when set; otherwise the agent cwd.
 */
export function resolveWhiteboxCodebaseRoot(input: {
  agentCwd: string;
  codebasePath?: string;
}): string {
  return resolve(normalize(input.codebasePath ?? input.agentCwd));
}

/**
 * Return true when `candidate` is lexically under `root` (after normalization).
 * Catches `..` traversals, Windows cross-drive escapes (relative() returns an
 * absolute path), and empty-string edge cases.
 */
function isUnderRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  if (rel === "") return true;
  if (rel.startsWith("..") || isAbsolute(rel)) return false;
  return true;
}

/**
 * Resolve `subPath` (file or directory) under `root` and reject escapes.
 * Validates both the lexical path and, when the target exists on disk, the
 * real (symlink-resolved) path to prevent symlink-based containment bypasses.
 */
export function resolvePathWithinCodebaseRoot(
  root: string,
  subPath: string = ".",
): string {
  const absRoot = resolve(normalize(root));
  if (subPath.startsWith("/")) {
    throw new Error(
      `Absolute subPath not allowed (must be relative to codebase root): ${subPath}`,
    );
  }
  const candidate = resolve(absRoot, normalize(subPath));

  if (!isUnderRoot(absRoot, candidate)) {
    throw new Error(`Path escapes codebase root: ${subPath}`);
  }

  if (existsSync(candidate)) {
    const realCandidate = realpathSync(candidate);
    const realRoot = realpathSync(absRoot);
    if (!isUnderRoot(realRoot, realCandidate)) {
      throw new Error(`Path escapes codebase root via symlink: ${subPath}`);
    }
  }

  return candidate;
}

/**
 * Resolve a session-relative artifact path for reading. Only
 * `logs/whitebox/...` and `scratchpad/whitebox/...` under `session.rootPath` are allowed.
 */
export function resolveSessionWhiteboxArtifactPath(input: {
  sessionRootPath: string;
  artifactRelativePath: string;
}): string {
  const normalized = normalize(input.artifactRelativePath).replace(/\\/g, "/");
  if (normalized.includes("..")) {
    throw new Error("Invalid artifact path");
  }
  const posixPath = normalized.startsWith("/")
    ? normalized.slice(1)
    : normalized;
  const allowed =
    posixPath.startsWith("logs/whitebox/") ||
    posixPath.startsWith("scratchpad/whitebox/");
  if (!allowed) {
    throw new Error(
      `Artifact path must start with logs/whitebox/ or scratchpad/whitebox/: ${input.artifactRelativePath}`,
    );
  }
  const resolved = resolve(input.sessionRootPath, posixPath);

  if (!isUnderRoot(resolve(input.sessionRootPath), resolved)) {
    throw new Error("Invalid artifact path");
  }

  if (existsSync(resolved)) {
    const realResolved = realpathSync(resolved);
    const realRoot = realpathSync(input.sessionRootPath);
    if (!isUnderRoot(realRoot, realResolved)) {
      throw new Error("Artifact path escapes session root via symlink");
    }
  }

  return resolved;
}
