/**
 * Shared backend helpers: path containment, output spill, and the base64
 * sandbox write.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { agentLogsDir } from "../../agents/offSecAgent/tools/agentScratch";
import type { UnifiedSandbox } from "../../agents/offSecAgent/tools/sandbox";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";

/** Readability extract caps, chars / ms. */
export const CAPS = {
  READABILITY_MAX_CHARS: 50_000,
  READABILITY_TIMEOUT_MS: 30_000,
  /** Inline cap before command / http output spills to a file. */
  EXEC_MAX_INLINE: 50_000,
} as const;

/**
 * Resolve `target` against `root` and assert it stays under it. Lexical only —
 * matching the three copies this replaces (`applyPatch`, `deleteFile`, `glob`),
 * none of which resolve symlinks. Throws when the path escapes.
 */
export function resolveContained(root: string, target: string): string {
  const resolved = isAbsolute(target) ? target : resolve(root, target);
  const rel = relative(root, resolved);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path escapes agent working directory: ${target}`);
  }
  return resolved;
}

/**
 * Redact known secret values from text. Longest-first to avoid partial masking;
 * skip values under 6 chars so they can't corrupt output.
 */
export function redactSecretValues(text: string, secrets?: string[]): string {
  if (!secrets?.length) return text;
  let out = text;
  for (const s of [...secrets]
    .filter((v) => v && v.length >= 6)
    .sort((a, b) => b.length - a.length)) {
    out = out.split(s).join("[REDACTED]");
  }
  return out;
}

const MS_TIMEOUT_THRESHOLD = 10_000;

/**
 * Normalize obviously-millisecond timeout values into seconds. The contract is
 * seconds, but models sometimes emit `30000` / `120000`.
 */
export function normalizeExecuteCommandTimeout(
  timeout?: number,
): number | undefined {
  if (timeout == null || !Number.isFinite(timeout) || timeout <= 0) {
    return undefined;
  }
  if (timeout >= MS_TIMEOUT_THRESHOLD) {
    return Math.max(1, Math.ceil(timeout / 1_000));
  }
  return timeout;
}

/**
 * If `raw` exceeds the inline cap, save the full text under this agent's log
 * dir (`cmd-output/`) and return truncated text + file path; otherwise return
 * the text as-is. Scoped per-subagent via {@link agentLogsDir}.
 */
export function maybeSaveFullOutput(
  raw: string,
  ctx: ToolContext,
): { text: string; file?: string } {
  if (raw.length <= CAPS.EXEC_MAX_INLINE) {
    return { text: raw || "(no output)" };
  }

  const outputDir = join(agentLogsDir(ctx), "cmd-output");
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filePath = join(outputDir, `output-${ts}.txt`);

  try {
    writeFileSync(filePath, raw);
  } catch {
    return {
      text: `${raw.substring(0, CAPS.EXEC_MAX_INLINE)}...\n\n(truncated — failed to save full output to file)`,
    };
  }

  return {
    text: `${raw.substring(0, CAPS.EXEC_MAX_INLINE)}...\n\n(truncated — full output saved to ${filePath}). Use read_file or grep to analyze.`,
    file: filePath,
  };
}

/**
 * Read a file inside a sandbox as base64, returning null when it does not
 * exist and "" when it exists but is empty.
 */
export async function readViaSandbox(
  sandbox: UnifiedSandbox,
  path: string,
): Promise<string | null> {
  const result = await sandbox.execute(
    `test -f "${path}" && cat "${path}" | base64 -w 0`,
  );
  if (!result.success || !result.stdout.trim()) {
    const exists = await sandbox.execute(`test -f "${path}"`);
    if (exists.exitCode !== 0) return null;
    return "";
  }
  return Buffer.from(result.stdout.trim(), "base64").toString("utf-8");
}

/** Write a file inside a sandbox via a base64 echo, creating parent dirs. */
export async function writeViaSandbox(
  sandbox: UnifiedSandbox,
  path: string,
  content: string,
): Promise<void> {
  await sandbox.execute(`mkdir -p "${dirname(path)}"`);
  const b64 = Buffer.from(content).toString("base64");
  const result = await sandbox.execute(`echo "${b64}" | base64 -d > "${path}"`);
  if (!result.success) {
    throw new Error(result.stderr || `Failed to write ${path} in sandbox`);
  }
}

/** Delete a file inside a sandbox. */
export async function deleteViaSandbox(
  sandbox: UnifiedSandbox,
  path: string,
): Promise<void> {
  const result = await sandbox.execute(`rm "${path}"`);
  if (!result.success) {
    throw new Error(result.stderr || `Failed to delete ${path} in sandbox`);
  }
}
