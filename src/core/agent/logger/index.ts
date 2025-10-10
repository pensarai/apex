import type { Session } from "../sessions";
import { appendFileSync, existsSync, mkdirSync } from "fs";
import path from "path";

export enum LogLevel {
  INFO = "INFO",
  ERROR = "ERROR",
  DEBUG = "DEBUG",
  WARN = "WARN",
  LOG = "LOG",
}

export class Logger {
  private session: Session;
  private logFilePath: string;

  constructor(session: Session) {
    this.session = session;
    this.logFilePath = path.join(session.logsPath, "agent.log");

    // Ensure logs directory exists
    if (!existsSync(session.logsPath)) {
      mkdirSync(session.logsPath, { recursive: true });
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
  public getSession(): Session {
    return this.session;
  }
}
