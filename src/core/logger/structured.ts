import { writeErrorLog } from "./index";

// SCREAMING_SNAKE to match the Console logLevel flag value (PENSAR_LOG_LEVEL),
// passed verbatim. Method names stay lowercase (logger.debug()).
export type LogLevel = "DEBUG" | "INFO" | "WARN" | "ERROR" | "SILENT";

const SEVERITY: Record<LogLevel, number> = {
  DEBUG: 10,
  INFO: 20,
  WARN: 30,
  ERROR: 40,
  SILENT: 50,
};

const VALID_LEVELS = new Set<LogLevel>([
  "DEBUG",
  "INFO",
  "WARN",
  "ERROR",
  "SILENT",
]);

function isLevel(v: unknown): v is LogLevel {
  return typeof v === "string" && VALID_LEVELS.has(v as LogLevel);
}

type Fields = Record<string, unknown>;
type Env = Record<string, string | undefined>;

/**
 * Resolve the initial log level from env (first match wins):
 * CLI flag (pre-baked into PENSAR_LOG_LEVEL by cli.ts) > PENSAR_LOG_LEVEL >
 * PENSAR_DEBUG in {1,true} ⇒ debug > default info.
 */
export function resolveInitialLevel(env: Env): LogLevel {
  // `PENSAR_LOG_LEVEL` carries the flag value verbatim (e.g. `DEBUG`). Parse
  // case-insensitively at this boundary, normalizing to the canonical token.
  const explicit = env.PENSAR_LOG_LEVEL?.trim().toUpperCase();
  if (isLevel(explicit)) return explicit;

  const debug = env.PENSAR_DEBUG?.toLowerCase();
  if (debug === "1" || debug === "true") return "DEBUG";

  return "INFO";
}

function resolveFormat(env: Env): "json" | "pretty" {
  const forced = env.PENSAR_LOG_FORMAT?.toLowerCase();
  if (forced === "json" || forced === "pretty") return forced;
  return process.stderr.isTTY ? "pretty" : "json";
}

const COLORS: Record<LogLevel, string> = {
  DEBUG: "\x1b[90m", // gray
  INFO: "\x1b[36m", // cyan
  WARN: "\x1b[33m", // yellow
  ERROR: "\x1b[31m", // red
  SILENT: "",
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

// Sink for emitted log lines. Defaults to stderr; the interactive TUI redirects
// this to a file (see `routeLogsToErrorFile`) so a raw terminal write never
// corrupts the OpenTUI frame while it owns the screen.
type LogSink = (line: string) => void;
const stderrSink: LogSink = (line) => process.stderr.write(`${line}\n`);
let sink: LogSink = stderrSink;

export function setLogSink(next: LogSink | null): void {
  sink = next ?? stderrSink;
}

class Logger {
  private level: LogLevel;
  private explicit = false;
  private scope: string | undefined;

  constructor(scope?: string, level?: LogLevel) {
    this.scope = scope;
    this.level = level ?? resolveInitialLevel(process.env);
  }

  setLevel(level: LogLevel): void {
    this.level = level;
    this.explicit = true;
  }

  getLevel(): LogLevel {
    return this.level;
  }

  child(scope: string): Logger {
    const next = this.scope ? `${this.scope}:${scope}` : scope;
    const child = new Logger(next, this.level);
    if (this.explicit) child.setLevel(this.level);
    return child;
  }

  debug(msg: string, fields?: Fields): void {
    this.emit("DEBUG", msg, fields);
  }

  info(msg: string, fields?: Fields): void {
    this.emit("INFO", msg, fields);
  }

  warn(msg: string, fields?: Fields): void {
    this.emit("WARN", msg, fields);
  }

  error(msg: string, errOrFields?: unknown, fields?: Fields): void {
    let err: Error | undefined;
    let extra: Fields | undefined;

    if (errOrFields instanceof Error) {
      err = errOrFields;
      extra = fields;
    } else if (errOrFields && typeof errOrFields === "object") {
      extra = errOrFields as Fields;
    }

    const merged: Fields = { ...extra };
    if (err) {
      merged.error = err.message;
      if (err.stack) merged.stack = err.stack;
    }

    this.emit("ERROR", msg, merged);

    // Back-compat: mirror errors to ~/.pensar/error.log.
    // Respect `SILENT` — if the user explicitly silenced all output, don't persist either.
    if (this.level !== "SILENT") {
      writeErrorLog(err ?? msg, this.scope, extra);
    }
  }

  private emit(level: LogLevel, msg: string, fields?: Fields): void {
    if (SEVERITY[level] < SEVERITY[this.level]) return;

    const ts = new Date().toISOString();
    const format = resolveFormat(process.env);
    const line =
      format === "json"
        ? this.formatJson(ts, level, msg, fields)
        : this.formatPretty(ts, level, msg, fields);

    sink(line);
  }

  private formatJson(
    ts: string,
    level: LogLevel,
    msg: string,
    fields?: Fields,
  ): string {
    const record: Fields = { ts, level, msg };
    if (this.scope) record.scope = this.scope;
    if (fields) {
      for (const [k, v] of Object.entries(fields)) {
        if (k !== "ts" && k !== "level" && k !== "msg" && k !== "scope") {
          record[k] = v;
        }
      }
    }
    return safeStringify(record);
  }

  private formatPretty(
    ts: string,
    level: LogLevel,
    msg: string,
    fields?: Fields,
  ): string {
    const color = COLORS[level];
    const tag = `${color}${level.padEnd(5)}${RESET}`;
    const scope = this.scope ? ` ${DIM}[${this.scope}]${RESET}` : "";
    let rest = "";
    if (fields && Object.keys(fields).length > 0) {
      rest = ` ${DIM}${safeStringify(fields)}${RESET}`;
    }
    return `${DIM}${ts}${RESET} ${tag}${scope} ${msg}${rest}`;
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return JSON.stringify({ msg: "[unserializable log payload]" });
  }
}

export type { Logger };

export function createLogger(scope?: string): Logger {
  return new Logger(scope);
}

export const logger = new Logger();
