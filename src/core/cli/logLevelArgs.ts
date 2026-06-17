import type { StructuredLogLevel } from "../logger";

const VALID_LOG_LEVELS = new Set<StructuredLogLevel>([
  "DEBUG",
  "INFO",
  "WARN",
  "ERROR",
  "SILENT",
]);

export interface CliLogLevelResult {
  /** Effective level, or undefined to use the env/default. */
  level: StructuredLogLevel | undefined;
  /** The rejected value, if the winning --log-level was invalid/missing. */
  invalid?: string;
}

/**
 * Resolve the diagnostic log level from CLI flags, stripping them (and the
 * `--log-level` value) from `argv` in place so they don't collide with
 * per-command parsing. `--log-level <lvl>` wins over `--verbose` (DEBUG) /
 * `--quiet` (WARN); the rightmost occurrence wins. Case-insensitive.
 *
 * An invalid winning `--log-level` never aborts the CLI: it's reported via
 * `invalid` (the caller surfaces it) and the level falls back to any shorthand,
 * else the env/default.
 */
export function resolveCliLogLevel(argv: string[]): CliLogLevelResult {
  let logLevelValue: StructuredLogLevel | undefined;
  let shorthandLevel: StructuredLogLevel | undefined;
  let sawLogLevel = false;
  let invalid: string | undefined;
  for (let i = argv.length - 1; i >= 0; i--) {
    const a = argv[i]!;
    if (a === "--verbose") {
      shorthandLevel ??= "DEBUG";
      argv.splice(i, 1);
    } else if (a === "--quiet") {
      shorthandLevel ??= "WARN";
      argv.splice(i, 1);
    } else if (a === "--log-level") {
      // A real value never starts with "-". If the next token is missing or is
      // another flag, treat the value as missing and DON'T consume that token.
      const next = argv[i + 1];
      const valueToken =
        next !== undefined && !next.startsWith("-") ? next : undefined;
      // Reverse scan: the first --log-level seen is the rightmost, which wins.
      // Only validate that one; earlier (overridden) pairs are ignored.
      if (!sawLogLevel) {
        sawLogLevel = true;
        const upper = valueToken?.toUpperCase();
        if (upper && VALID_LOG_LEVELS.has(upper as StructuredLogLevel)) {
          logLevelValue = upper as StructuredLogLevel;
        } else {
          invalid = valueToken ?? "(missing)";
        }
      }
      argv.splice(i, valueToken !== undefined ? 2 : 1);
    }
  }
  return { level: logLevelValue ?? shorthandLevel, invalid };
}
