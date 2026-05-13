import { normalize, relative, resolve } from "node:path";

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
 * Resolve `subPath` (file or directory) under `root` and reject `..` escapes.
 * `subPath` may be absolute only if it still lies under `root` after resolution.
 */
export function resolvePathWithinCodebaseRoot(
  root: string,
  subPath: string = ".",
): string {
  const absRoot = resolve(normalize(root));
  const candidate = subPath.startsWith("/")
    ? resolve(normalize(subPath))
    : resolve(absRoot, normalize(subPath));
  const rel = relative(absRoot, candidate);
  if (rel.startsWith("..") || rel === "..") {
    throw new Error(`Path escapes codebase root: ${subPath}`);
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
  const posixPath = normalized.startsWith("/") ? normalized.slice(1) : normalized;
  const allowed =
    posixPath.startsWith("logs/whitebox/") ||
    posixPath.startsWith("scratchpad/whitebox/");
  if (!allowed) {
    throw new Error(
      `Artifact path must start with logs/whitebox/ or scratchpad/whitebox/: ${input.artifactRelativePath}`,
    );
  }
  return resolve(input.sessionRootPath, posixPath);
}
