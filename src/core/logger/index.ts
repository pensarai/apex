import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { type SessionInfo, sessions } from "../session";

export { type LogLevel as StructuredLogLevel, logger } from "./structured";

import { setLogSink } from "./structured";

export enum LogLevel {
  INFO = "INFO",
  ERROR = "ERROR",
  DEBUG = "DEBUG",
  WARN = "WARN",
  LOG = "LOG",
}

const ERROR_LOG_PATH = path.join(os.homedir(), ".pensar", "error.log");
const RETENTION_DAYS = 7;
// error.log holds two line shapes: the human `<ts> - [LEVEL]` entries from
// writeErrorLog, and structured JSON lines (`{"ts":"<ts>",...}`) that the TUI
// sink appends. Prune must recognize both, or a recent JSON line following an
// expired human entry inherits its drop decision and gets deleted.
const TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2}T[\d:.]+Z) - /;
const JSON_TS_RE = /^\{"ts":"(\d{4}-\d{2}-\d{2}T[\d:.]+Z)"/;

/**
 * ISO timestamp starting a log entry, from either shape. Returns null for
 * continuation lines (e.g. stack-trace lines) that carry no timestamp of their
 * own — those inherit the preceding entry's keep decision.
 */
function entryTimestamp(line: string): number | null {
  const m = TIMESTAMP_RE.exec(line) ?? JSON_TS_RE.exec(line);
  return m ? new Date(m[1]!).getTime() : null;
}

let hasPruned = false;

/**
 * Drop log entries older than RETENTION_DAYS. Runs at most once per process.
 */
function pruneErrorLog(): void {
  if (hasPruned) return;
  hasPruned = true;

  try {
    if (!existsSync(ERROR_LOG_PATH)) return;

    const cutoff = Date.now() - RETENTION_DAYS * 86_400_000;
    const raw = readFileSync(ERROR_LOG_PATH, "utf8");
    const lines = raw.split("\n");

    const kept: string[] = [];
    let keeping = true;
    for (const line of lines) {
      const ts = entryTimestamp(line);
      if (ts !== null) {
        keeping = ts >= cutoff;
      }
      if (keeping) {
        kept.push(line);
      }
    }

    writeFileSync(ERROR_LOG_PATH, kept.join("\n"), "utf8");
  } catch {
    // Don't let pruning failures break anything
  }
}

/**
 * Append an error entry to ~/.pensar/error.log.
 * Safe to call from anywhere — no session required.
 *
 * @param error  The error value (Error instance or anything stringifiable)
 * @param source Optional tag identifying the subsystem, e.g. "TUI", "CORE"
 * @param fields Optional structured context, persisted so the file is
 *               diagnosable on its own (matches the stderr JSON record)
 */
export function writeErrorLog(
  error: unknown,
  source?: string,
  fields?: Record<string, unknown>,
): void {
  try {
    pruneErrorLog();

    const dir = path.dirname(ERROR_LOG_PATH);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    const timestamp = new Date().toISOString();
    const tag = source ? `[${source}] ` : "";
    const message =
      error instanceof Error
        ? `${error.message}\n${error.stack ?? ""}`
        : String(error);
    let fieldsStr = "";
    if (fields && Object.keys(fields).length > 0) {
      try {
        fieldsStr = ` ${JSON.stringify(fields)}`;
      } catch {
        // Drop unserializable fields rather than fail the write.
      }
    }
    const entry = `${timestamp} - [ERROR] ${tag}${message}${fieldsStr}\n`;

    appendFileSync(ERROR_LOG_PATH, entry, "utf8");
  } catch {
    // Last resort — don't throw from the error logger
  }
}

/**
 * Redirect all structured-logger output from stderr into ~/.pensar/error.log.
 *
 * The interactive TUI calls this at startup: OpenTUI owns the screen, so any
 * raw stderr write (a `log.warn`, a stack trace) lands on the live frame and
 * garbles it — e.g. the per-turn Weave flush warning bleeding into the input
 * box. User-facing errors are surfaced through the TUI itself; the file keeps
 * everything diagnosable. Headless/CLI runs never call this, so they keep
 * logging to stderr as before.
 */
export function routeLogsToErrorFile(): void {
  // Force JSON so pretty-format ANSI color codes don't end up in the file.
  process.env.PENSAR_LOG_FORMAT = "json";
  setLogSink((line) => {
    try {
      const dir = path.dirname(ERROR_LOG_PATH);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      appendFileSync(ERROR_LOG_PATH, `${line}\n`, "utf8");
    } catch {
      // Last resort — never throw from the logger.
    }
  });
}

export class Logger {
  private session: SessionInfo;
  private logFilePath: string;

  constructor(session: SessionInfo, fileName?: string) {
    this.session = session;
    const rootPath = sessions.getSessionRoot(session.id);
    const logsPath = path.join(rootPath, "logs");
    this.logFilePath = path.join(logsPath, fileName || "agent.log");

    // Ensure logs directory exists
    if (!existsSync(logsPath)) {
      mkdirSync(logsPath, { recursive: true });
    }
  }

  /**
   * Write a log message to the log file
   */
  private writeLog(level: LogLevel, message: string): void {
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} - [${level}] ${message}\n`;

    try {
      appendFileSync(this.logFilePath, logEntry, "utf8");
    } catch (error) {
      console.error(`Failed to write to log file: ${error}`);
    }
  }

  /**
   * Log a general message
   */
  public log(message: string): void {
    this.writeLog(LogLevel.LOG, message);
  }

  /**
   * Log an info message
   */
  public info(message: string): void {
    this.writeLog(LogLevel.INFO, message);
  }

  /**
   * Log an error message
   */
  public error(message: string): void {
    this.writeLog(LogLevel.ERROR, message);
  }

  /**
   * Log a debug message
   */
  public debug(message: string): void {
    this.writeLog(LogLevel.DEBUG, message);
  }

  /**
   * Log a warning message
   */
  public warn(message: string): void {
    this.writeLog(LogLevel.WARN, message);
  }

  /**
   * Get the current log file path
   */
  public getLogFilePath(): string {
    return this.logFilePath;
  }

  /**
   * Get the session associated with this logger
   */
  public getSession(): SessionInfo {
    return this.session;
  }
}
