import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Absolute paths to the wordlists bundled inside the published package.
 *
 * Tiers are chosen by signal, not by ladder — see {@link getBundledWordlists}.
 */
export interface BundledWordlists {
  /** ~200 entries — sub-second probes, time-pressured runs, smoke checks. */
  tiny: string;
  /** ~4.7k entries — default for normal recon. */
  common: string;
  /** ~30k entries — escalation only. */
  large: string;
}

const RELATIVE = {
  tiny: "assets/wordlists/tiny.txt",
  common: "assets/wordlists/common.txt",
  large: "assets/wordlists/large.txt",
} as const;

let cached: BundledWordlists | null | undefined;

/**
 * Walk up from `start` until we find a directory that contains both
 * `package.json` (with `name === "@pensar/apex"`) and `assets/wordlists/`.
 *
 * Returns the absolute path to that directory, or `null` if the walk
 * reaches the filesystem root without finding a match.
 *
 * Walking up rather than using a fixed relative path keeps resolution
 * robust across:
 *   - dev runs from source (`bun run start` → `src/...`)
 *   - the bundled CLI (`build/cli.js`)
 *   - test runs (vitest spawns from various cwds)
 *   - global npm installs (assets sit alongside `build/` under the install root)
 */
function findPackageRoot(start: string): string | null {
  let dir = start;
  while (true) {
    const pkgPath = join(dir, "package.json");
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
          name?: string;
        };
        if (
          pkg.name === "@pensar/apex" &&
          existsSync(join(dir, "assets", "wordlists"))
        ) {
          return dir;
        }
      } catch {
        // ignored — keep walking
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * Resolve absolute paths to the bundled wordlists.
 *
 * Returns `null` if the assets directory is not present at runtime — for
 * example, in a `bun build --compile` binary that didn't bundle them.
 * Callers must degrade gracefully: do NOT inject paths into prompts when
 * this returns `null`.
 *
 * Result is cached after the first call.
 */
export function getBundledWordlists(): BundledWordlists | null {
  if (cached !== undefined) return cached;

  const here = dirname(fileURLToPath(import.meta.url));
  const root = findPackageRoot(here);
  if (root === null) {
    cached = null;
    return cached;
  }

  const paths: BundledWordlists = {
    tiny: resolve(root, RELATIVE.tiny),
    common: resolve(root, RELATIVE.common),
    large: resolve(root, RELATIVE.large),
  };

  for (const p of Object.values(paths)) {
    if (!existsSync(p) || statSync(p).size === 0) {
      cached = null;
      return cached;
    }
  }

  cached = paths;
  return cached;
}

/**
 * Reset the in-memory cache. Test-only — production code should never need
 * to re-resolve paths within a single process lifetime.
 *
 * @knipignore test hook for resetting the module-level cache.
 */
export function _resetBundledWordlistsCacheForTests(): void {
  cached = undefined;
}
