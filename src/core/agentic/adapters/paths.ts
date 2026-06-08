import type { AgenticAdapterConfig } from "../config";

/** Read a value from a nested object by dot-path (supports numeric indices). */
export function getByPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const key of path.split(".")) {
    if (cur == null) return undefined;
    if (Array.isArray(cur)) {
      const idx = Number(key);
      cur = Number.isInteger(idx) ? cur[idx] : undefined;
    } else if (typeof cur === "object") {
      cur = (cur as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return cur;
}

/** Set a value at a dot-path, creating intermediate objects as needed. */
export function setByPath(
  obj: Record<string, unknown>,
  path: string,
  value: unknown,
): void {
  const keys = path.split(".");
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i]!;
    if (typeof cur[key] !== "object" || cur[key] == null) cur[key] = {};
    cur = cur[key] as Record<string, unknown>;
  }
  cur[keys[keys.length - 1]!] = value;
}

/** Coerce a path lookup result to text the oracle can scan. */
export function asText(value: unknown): string {
  if (value == null) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** Build auth headers from adapter config, reading the secret from env. */
export function authHeaders(cfg: AgenticAdapterConfig): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const env = cfg.auth?.valueEnv;
  const value = env ? process.env[env] : undefined;
  if (value) {
    const name = cfg.auth?.header ?? "Authorization";
    const scheme = cfg.auth?.scheme ?? "bearer";
    headers[name] = scheme === "bearer" ? `Bearer ${value}` : value;
  }
  return headers;
}
