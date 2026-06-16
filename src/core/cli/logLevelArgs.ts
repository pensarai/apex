import type { StructuredLogLevel } from "../logger";

const VALID_LOG_LEVELS = new Set<StructuredLogLevel>([
  "DEBUG",
  "INFO",
  "WARN",
  "ERROR",
  "SILENT",
]);

export class CliLogLevelError extends Error {}

/**
 * Resolve the diagnostic log level from CLI flags, stripping them (and the
 * `--log-level` value) from `argv` in place so they don't collide with
 * per-command parsing. `--log-level <lvl>` wins over `--verbose` (DEBUG) /
 * `--quiet` (WARN); the rightmost occurrence wins. Case-insensitive. Throws
 * `CliLogLevelError` on a missing/invalid `--log-level` value.
 */
export function resolveCliLogLevel(
  argv: string[],
): StructuredLogLevel | undefined {
  let logLevelValue: StructuredLogLevel | undefined;
  let shorthandLevel: StructuredLogLevel | undefined;
  for (let i = argv.length - 1; i >= 0; i--) {
    const a = argv[i]!;
    if (a === "--verbose") {
      shorthandLevel ??= "DEBUG";
      argv.splice(i, 1);
    } else if (a === "--quiet") {
      shorthandLevel ??= "WARN";
      argv.splice(i, 1);
    } else if (a === "--log-level") {
      const value = argv[i + 1]?.toUpperCase();
      if (value && VALID_LOG_LEVELS.has(value as StructuredLogLevel)) {
        logLevelValue ??= value as StructuredLogLevel;
        argv.splice(i, 2);
      } else {
        throw new CliLogLevelError(
          "Error: --log-level expects one of DEBUG|INFO|WARN|ERROR|SILENT",
        );
      }
    }
  }
  return logLevelValue ?? shorthandLevel;
}
