import {
  mkdirSync,
  existsSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  statSync,
  rmSync,
} from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomBytes } from "crypto";
import { runDnsOwnershipCheck } from "./ownershipCheck";

export interface Session {
  id: string;
  rootPath: string;
  findingsPath: string;
  scratchpadPath: string;
  logsPath: string;
  target: string;
  objective: string;
  startTime: string;
}

/**
 * Generate a unique session ID
 */
function generateSessionId(prefix?: string): string {
  const timestamp = Date.now().toString(36);
  return `${prefix ? `${prefix}-` : ""}${timestamp}`;
}

/**
 * Get the base Pensar directory path
 */
export function getPensarDir(): string {
  return join(homedir(), ".pensar");
}

/**
 * Get the executions directory path
 */
export function getExecutionsDir(): string {
  return join(getPensarDir(), "executions");
}

/**
 * Create a new session for a pentest run
 */
export function createSession(
  target: string,
  objective?: string,
  prefix?: string
): Session {
  const sessionId = generateSessionId(prefix);
  const rootPath = join(getExecutionsDir(), sessionId);
  const findingsPath = join(rootPath, "findings");
  const scratchpadPath = join(rootPath, "scratchpad");
  const logsPath = join(rootPath, "logs");

  // Create directory structure
  ensureDirectoryExists(rootPath);
  ensureDirectoryExists(findingsPath);
  ensureDirectoryExists(scratchpadPath);
  ensureDirectoryExists(logsPath);

  const isDomainAllowed = await runDnsOwnershipCheck(target);

  if(!isDomainAllowed) {
    throw new Error(`Cannot create session: ownership check did not pass for target: ${target}`);
  }

  const session: Session = {
    id: sessionId,
    rootPath,
    findingsPath,
    scratchpadPath,
    logsPath,
    target,
    objective: objective ?? "",
    startTime: new Date().toISOString(),
  };

  // TODO: check if remote target and perform dns ownership check

  // Write session metadata
  const metadataPath = join(rootPath, "session.json");
  writeFileSync(metadataPath, JSON.stringify(session, null, 2));

  // Create initial README
  const readmePath = join(rootPath, "README.md");
  const readme = `# Penetration Test Session

**Session ID:** ${sessionId}
**Target:** ${target}
**Objective:** ${objective}
**Started:** ${session.startTime}

## Directory Structure

- \`findings/\` - Security findings and vulnerabilities
- \`scratchpad/\` - Notes and temporary data during testing
- \`logs/\` - Execution logs and command outputs
- \`session.json\` - Session metadata

## Findings

Security findings will be documented in the \`findings/\` directory as individual files.

## Status

Testing in progress...
`;

  writeFileSync(readmePath, readme);

  return session;
}

/**
 * Ensure a directory exists, creating it if necessary
 */
function ensureDirectoryExists(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

/**
 * Get a session by ID
 */
export function getSession(sessionId: string): Session | null {
  const sessionPath = join(getExecutionsDir(), sessionId);
  const metadataPath = join(sessionPath, "session.json");

  if (!existsSync(metadataPath)) {
    return null;
  }

  const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));
  return metadata as Session;
}

/**
 * List all sessions
 */
export function listSessions(): string[] {
  const executionsDir = getExecutionsDir();

  if (!existsSync(executionsDir)) {
    return [];
  }

  const entries = readdirSync(executionsDir);

  return entries.filter((entry: string) => {
    const fullPath = join(executionsDir, entry);
    return statSync(fullPath).isDirectory();
  });
}

/**
 * Clean up old sessions (optional utility)
 */
export function cleanupOldSessions(daysOld: number = 30): number {
  const executionsDir = getExecutionsDir();

  if (!existsSync(executionsDir)) {
    return 0;
  }

  const entries = readdirSync(executionsDir);
  const now = Date.now();
  const cutoff = now - daysOld * 24 * 60 * 60 * 1000;
  let cleaned = 0;

  for (const entry of entries) {
    const fullPath = join(executionsDir, entry);
    const stats = statSync(fullPath);

    if (stats.isDirectory() && stats.mtimeMs < cutoff) {
      rmSync(fullPath, { recursive: true, force: true });
      cleaned++;
    }
  }

  return cleaned;
}
