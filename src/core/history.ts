/**
 * Persistent command history stored at ~/.pensar/command-history.json
 *
 * Lazily loads from disk on first access. Writes are fire-and-forget
 * so callers never block on I/O. The in-memory array is the source
 * of truth after initial load; disk is kept in sync best-effort.
 */

import * as Storage from "./storage";

const STORAGE_KEY = ["command-history"];
const MAX_ENTRIES = 500;

let entries: string[] | null = null;
let loadPromise: Promise<void> | null = null;

async function ensureLoaded(): Promise<string[]> {
  if (entries !== null) return entries;
  if (!loadPromise) {
    loadPromise = (async () => {
      try {
        const data = await Storage.read<string[]>(STORAGE_KEY);
        entries = Array.isArray(data) ? data : [];
      } catch {
        entries = [];
      }
    })();
  }
  await loadPromise;
  return entries!;
}

/**
 * Load history from disk (or return cached entries).
 * Call once at startup; subsequent calls return immediately.
 */
export async function load(): Promise<string[]> {
  return ensureLoaded();
}

/**
 * Append an entry. Skips consecutive duplicates.
 * Persists to disk in the background.
 *
 * Sanitizes secrets from `/headers add|set|import` and the CLI
 * `--header "Name: Value"` flag before persisting. We never want a
 * recalled history entry to leak an Authorization token onto disk or
 * into the live recall buffer.
 */
export async function push(entry: string): Promise<void> {
  const sanitized = redactSecretsInHistoryEntry(entry);
  const history = await ensureLoaded();
  if (history[history.length - 1] === sanitized) return;
  history.push(sanitized);
  if (history.length > MAX_ENTRIES) {
    history.splice(0, history.length - MAX_ENTRIES);
  }
  Storage.write(STORAGE_KEY, history).catch(() => {});
}

/**
 * Replace any `Name: Value` payload that follows a known header
 * subcommand with `Name: <redacted>`. Conservative on purpose:
 * a false positive only hides a benign value, but a false negative
 * persists a secret. The Name itself stays so recall is still useful.
 */
export function redactSecretsInHistoryEntry(entry: string): string {
  const trimmed = entry.trimStart();
  const slashMatch = trimmed.match(
    /^(\/headers\s+(?:add|set|import)\s+)(.+)$/i,
  );
  if (slashMatch) {
    const [, prefix, payload] = slashMatch;
    const colon = payload.indexOf(":");
    if (colon === -1) return entry;
    return `${entry.slice(0, entry.length - payload.length)}${payload.slice(0, colon)}: <redacted>`;
  }
  return entry.replace(
    /(--header(?:s-from)?[=\s]+)("?)([^"\s]+:)\s*(?:[^"]*(?=")|[^"\s]+)("?)/gi,
    (_, prefix, openQuote, namePart, closeQuote) =>
      `${prefix}${openQuote}${namePart} <redacted>${closeQuote}`,
  );
}

/**
 * Synchronous accessor — returns whatever is currently loaded.
 * Returns an empty array if load() hasn't resolved yet.
 */
export function getEntries(): string[] {
  return entries ?? [];
}
