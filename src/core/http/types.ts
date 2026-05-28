export type HeaderRecord = Record<string, string>;

/** Source layer of an effective header. Later layers win on collision. */
export type Layer = "global" | "session" | "credential" | "request";

export type EffectiveHeader = {
  readonly name: string;
  readonly value: string;
  readonly source: Layer;
};

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

/** Mask sensitive values to `****<last4>` unless `showSecrets` is true. */
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
