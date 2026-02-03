import { Session } from "../../session";
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
  private session: Session.SessionInfo;
  private logFilePath: string;

  constructor(session: Session.SessionInfo, fileName?: string) {
    this.session = session;
    const rootPath = Session.getExecutionRoot(session.id);
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
  public getSession(): Session.SessionInfo {
    return this.session;
  }
}
