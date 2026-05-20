/**
 * Shared types for the custom-headers subsystem.
 *
 * Headers flow through the codebase as plain `Record<string, string>`.
 * The Biome `noRestrictedGlobals` rule (see biome.jsonc) enforces that
 * agent tools route outbound HTTP through `targetFetch` —
 * INV-blessed-fetch — which is the single mechanism preventing raw
 * `fetch` from bypassing the resolver.
 */

export type HeaderRecord = Record<string, string>;

/**
 * Source layer of an effective header. Order matches precedence: later
 * layers win on key collision in the resolver.
 *
 * See INV-precedence-deterministic and INV-precedence-explicit-request.
 */
export type Layer = "global" | "session" | "credential" | "request";

export type EffectiveHeader = {
  readonly name: string;
  readonly value: string;
  readonly source: Layer;
};

/**
 * Lower-cased substring patterns that mark a header as sensitive.
 * Sensitive headers are masked in display.
 */
const SENSITIVE_PATTERNS = [
  "authorization",
  "cookie",
  "token",
  "key",
  "secret",
  "password",
] as const;

export function isSensitiveHeaderName(name: string): boolean {
  const lower = name.toLowerCase();
  return SENSITIVE_PATTERNS.some((p) => lower.includes(p));
}

/**
 * Render a header value safely for display. Sensitive values are masked
 * to the last four characters (`****abc1`). Pass `showSecrets` to
 * unmask for explicit user requests (`/headers list --show`).
 */
export function renderHeaderValue(
  name: string,
  value: string,
  showSecrets: boolean,
): string {
  if (showSecrets || !isSensitiveHeaderName(name)) {
    return value;
  }
  if (value.length <= 4) {
    return "****";
  }
  return `****${value.slice(-4)}`;
}
