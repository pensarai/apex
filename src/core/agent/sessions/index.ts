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
import { RateLimiter, type RateLimiterConfig } from '../../services/rateLimiter';
import { Identifier } from "../../id/id";

/**
 * @deprecated This module is deprecated. Use `core/session` instead.
 *
 * Migration guide:
 * - Import { Session } from '../../session' (or '../session' depending on path)
 * - Use Session.ExecutionSession type instead of Session
 * - Use await Session.createExecution({...}) instead of createSession(...)
 * - Use Session.DEFAULT_OUTCOME_GUIDANCE instead of DEFAULT_OUTCOME_GUIDANCE
 * - Use Session.BENCHMARK_OUTCOME_GUIDANCE instead of BENCHMARK_OUTCOME_GUIDANCE
 * - Use Session.getOffensiveHeaders(session) instead of getOffensiveHeaders(session)
 *
 * This module will be removed in a future version.
 */

// Re-export from new location for backward compatibility
import { Session } from "../../session";

/**
 * @deprecated Use Session.ExecutionSession from 'core/session' instead
 */
export type Session = Session.ExecutionSession;

/**
 * @deprecated Use Session.SessionConfig from 'core/session' instead
 */
export type SessionConfig = Session.SessionConfig;

/**
 * @deprecated Use Session.AuthCredentials from 'core/session' instead
 */
export type AuthCredentials = Session.AuthCredentials;

/**
 * @deprecated Use Session.OffensiveHeadersConfig from 'core/session' instead
 */
export type OffensiveHeadersConfig = Session.OffensiveHeadersConfig;

/**
 * @deprecated Use Session.ScopeConstraints from 'core/session' instead
 */
export type ScopeConstraints = Session.ScopeConstraints;

/**
 * @deprecated Use Session.DEFAULT_OFFENSIVE_HEADERS from 'core/session' instead
 */
export const DEFAULT_OFFENSIVE_HEADERS = Session.DEFAULT_OFFENSIVE_HEADERS;

/**
 * @deprecated Use Session.DEFAULT_OUTCOME_GUIDANCE from 'core/session' instead
 */
export const DEFAULT_OUTCOME_GUIDANCE = Session.DEFAULT_OUTCOME_GUIDANCE;

/**
 * @deprecated Use Session.BENCHMARK_OUTCOME_GUIDANCE from 'core/session' instead
 */
export const BENCHMARK_OUTCOME_GUIDANCE = Session.BENCHMARK_OUTCOME_GUIDANCE;

/**
 * @deprecated Use Session.getPensarDir() from 'core/session' instead
 */
export const getPensarDir = Session.getPensarDir;

/**
 * @deprecated Use Session.getExecutionsDir() from 'core/session' instead
 */
export const getExecutionsDir = Session.getExecutionsDir;

/**
 * @deprecated Use await Session.create({...}) from 'core/session' instead.
 * Note: The new function is async and has a different signature.
 *
 * This synchronous version is kept for backward compatibility with console.
 */
export function createSession(
  target: string,
  objective?: string,
  prefix?: string,
  config?: Session.SessionConfig
): Session.SessionInfo {
  const id = `${prefix ? prefix : ""}` + Identifier.descending('session');
  const rootPath = Session.getExecutionRoot(id);

  // Create directories synchronously
  mkdirSync(rootPath, { recursive: true });
  mkdirSync(join(rootPath, "findings"), { recursive: true });
  mkdirSync(join(rootPath, "scratchpad"), { recursive: true });
  mkdirSync(join(rootPath, "logs"), { recursive: true });
  mkdirSync(join(rootPath, "pocs"), { recursive: true });

  return {
    id,
    version: "1.0.0",
    targets: [target],
    name: objective || "pentest",
    time: { created: Date.now(), updated: Date.now() },
    config,
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
  };
}

/**
 * @deprecated Use Session.getOffensiveHeaders(session) from 'core/session' instead
 */
export const getOffensiveHeaders = Session.getOffensiveHeaders;
