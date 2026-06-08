import { writeErrorLog } from "./index";

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const SEVERITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 50,
};

const VALID_LEVELS = new Set<LogLevel>([
  "debug",
  "info",
  "warn",
  "error",
  "silent",
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
  const explicit = env.PENSAR_LOG_LEVEL?.toLowerCase();
  if (isLevel(explicit)) return explicit;

  const debug = env.PENSAR_DEBUG?.toLowerCase();
  if (debug === "1" || debug === "true") return "debug";

  return "info";
}

function resolveFormat(env: Env): "json" | "pretty" {
  const forced = env.PENSAR_LOG_FORMAT?.toLowerCase();
  if (forced === "json" || forced === "pretty") return forced;
  return process.stderr.isTTY ? "pretty" : "json";
}

const COLORS: Record<LogLevel, string> = {
  debug: "\x1b[90m", // gray
  info: "\x1b[36m", // cyan
  warn: "\x1b[33m", // yellow
  error: "\x1b[31m", // red
  silent: "",
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

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
    this.emit("debug", msg, fields);
  }

  info(msg: string, fields?: Fields): void {
    this.emit("info", msg, fields);
  }

  warn(msg: string, fields?: Fields): void {
    this.emit("warn", msg, fields);
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

    this.emit("error", msg, merged);

    // Back-compat: mirror errors to ~/.pensar/error.log.
    writeErrorLog(err ?? msg, this.scope);
  }

  private emit(level: LogLevel, msg: string, fields?: Fields): void {
    if (SEVERITY[level] < SEVERITY[this.level]) return;

    const ts = new Date().toISOString();
    const format = resolveFormat(process.env);
    const line =
      format === "json"
        ? this.formatJson(ts, level, msg, fields)
        : this.formatPretty(ts, level, msg, fields);

    process.stderr.write(`${line}\n`);
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
    const tag = `${color}${level.toUpperCase().padEnd(5)}${RESET}`;
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
