import { sessions, type SessionInfo } from "../session";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "fs";
import os from "os";
import path from "path";

export enum LogLevel {
  INFO = "INFO",
  ERROR = "ERROR",
  DEBUG = "DEBUG",
  WARN = "WARN",
  LOG = "LOG",
}

const ERROR_LOG_PATH = path.join(os.homedir(), ".pensar", "error.log");
const RETENTION_DAYS = 7;
const TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2}T[\d:.]+Z) - /;

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
    for (const line of lines) {
      const match = TIMESTAMP_RE.exec(line);
      if (match) {
        const ts = new Date(match[1]!).getTime();
        if (ts < cutoff) continue;
      }
      kept.push(line);
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
 */
export function writeErrorLog(error: unknown, source?: string): void {
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
    const entry = `${timestamp} - [ERROR] ${tag}${message}\n`;

    appendFileSync(ERROR_LOG_PATH, entry, "utf8");
  } catch {
    // Last resort — don't throw from the error logger
  }
}

export class Logger {
  private session: SessionInfo;
  private logFilePath: string;

  constructor(session: SessionInfo, fileName?: string) {
    this.session = session;
    const rootPath = sessions.getExecutionRoot(session.id);
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
