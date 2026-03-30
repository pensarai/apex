/**
 * Shared truncation utilities for tool results.
 *
 * Every tool that can return unbounded text to the model should use these
 * helpers to cap output size, keeping input-token costs predictable.
 */

/** Default cap for generic tool text results (chars). */
export const MAX_TOOL_RESULT_LENGTH = 50_000;

/** Cap for browser accessibility snapshots (chars). */
export const MAX_SNAPSHOT_LENGTH = 30_000;

/** Cap for browser evaluate / console results (chars). */
export const MAX_BROWSER_RESULT_LENGTH = 20_000;

/** Cap for sub-agent text output (chars). */
export const MAX_SUBAGENT_OUTPUT_LENGTH = 30_000;

/** Cap for headers serialized as part of an HTTP response (chars). */
export const MAX_HEADERS_LENGTH = 4_000;

/**
 * Truncate a string to `maxLen` characters, appending a notice when cut.
 * Returns the original string unchanged when within limits.
 */
export function truncateToolResult(
  text: string,
  maxLen: number,
  hint?: string,
): string {
  if (text.length <= maxLen) return text;
  const suffix = hint
    ? `\n\n(truncated at ${maxLen} chars — ${hint})`
    : `\n\n(truncated at ${maxLen} chars)`;
  return text.substring(0, maxLen) + suffix;
}

/**
 * Truncate a JSON-serializable value and return it as a string.
 * Useful for tool results that return structured objects which can be
 * arbitrarily large (e.g. browser evaluate results).
 */
export function truncateJsonResult(
  value: unknown,
  maxLen: number,
  hint?: string,
): string {
  const text =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return truncateToolResult(text, maxLen, hint);
}

/**
 * Cap the number of entries in a response headers record and
 * truncate individual header values that are excessively long.
 */
export function truncateHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const result: Record<string, string> = {};
  let totalLen = 0;

  for (const [key, value] of Object.entries(headers)) {
    const truncatedValue =
      value.length > 1_000
        ? value.substring(0, 1_000) + "...(truncated)"
        : value;

    totalLen += key.length + truncatedValue.length;

    if (totalLen > MAX_HEADERS_LENGTH) {
      result["_truncated"] =
        `Headers truncated at ${MAX_HEADERS_LENGTH} chars — ${Object.keys(headers).length - Object.keys(result).length} headers omitted`;
      break;
    }

    result[key] = truncatedValue;
  }

  return result;
}
