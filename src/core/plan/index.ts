/**
 * Plan File I/O Utilities
 *
 * Minimal sync helpers for reading/checking the pentest plan file
 * stored in each session directory at {session.rootPath}/plan.md.
 *
 * When a `subagentId` is provided, plan files are scoped per-agent
 * under `subagents/{subagentId}-plan.md` to avoid races when
 * multiple plan agents run concurrently.
 */

import { existsSync, readFileSync } from "fs";
import { join } from "path";

const PLAN_FILENAME = "plan.md";

/** Returns the absolute path to the plan file for a given session root. */
export function planFilePath(
  sessionRootPath: string,
  subagentId?: string,
): string {
  if (subagentId) {
    return join(sessionRootPath, "subagents", `${subagentId}-plan.md`);
  }
  return join(sessionRootPath, PLAN_FILENAME);
}

/** Reads the plan file content. Returns null if the file doesn't exist. */
export function readPlan(
  sessionRootPath: string,
  subagentId?: string,
): string | null {
  const path = planFilePath(sessionRootPath, subagentId);
  try {
    return readFileSync(path, "utf-8");
  } catch {
    return null;
  }
}

/** Returns true if a plan file exists in the session directory. */
export function hasPlan(sessionRootPath: string, subagentId?: string): boolean {
  return existsSync(planFilePath(sessionRootPath, subagentId));
}
