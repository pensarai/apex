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
 */
export async function push(entry: string): Promise<void> {
  const history = await ensureLoaded();
  if (history[history.length - 1] === entry) return;
  history.push(entry);
  if (history.length > MAX_ENTRIES) {
    history.splice(0, history.length - MAX_ENTRIES);
  }
  Storage.write(STORAGE_KEY, history).catch(() => {});
}

/**
 * Synchronous accessor — returns whatever is currently loaded.
 * Returns an empty array if load() hasn't resolved yet.
 */
export function getEntries(): string[] {
  return entries ?? [];
}
