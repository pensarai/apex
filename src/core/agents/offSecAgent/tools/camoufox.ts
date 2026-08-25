/**
 * Camoufox launch policy — the single source of truth for how the offensive
 * security agent launches its browser, shared by the local MCP path
 * ({@link ./playwrightMcp}) and the in-sandbox path ({@link ./sandboxPlaywright}).
 *
 * Camoufox (https://github.com/daijro/camoufox) is a patched Firefox that
 * injects a coherent, randomised fingerprint natively. It defeats the
 * `HeadlessChrome` / `navigator.webdriver` tells that get vanilla Playwright
 * browsers 403'd by WAFs on targets we are authorised to test.
 *
 * INVARIANT: every browser the agent launches is Camoufox. No launch site
 * hand-rolls its own Firefox/Chromium args — both paths feed
 * {@link CAMOUFOX_OPTIONS} into camoufox-js, which produces the
 * executablePath / args / env / firefoxUserPrefs that carry the fingerprint.
 */

import { execFile } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Our Camoufox configuration. JSON-serialisable so the sandbox path can embed
 * it verbatim in a generated script — the two paths stay in lockstep.
 *
 * Camoufox's defaults already produce a coherent random fingerprint; we only
 * add the two stealth/safety knobs that matter for recon. `headless` is set
 * per-environment by the caller, not here.
 */
export const CAMOUFOX_OPTIONS = {
  humanize: true, // human-like cursor movement (small latency cost, large stealth gain)
  block_webrtc: true, // stop WebRTC from leaking the real / local IP
  // ponytail: defaults cover UA/screen/timezone. Add geoip/proxy/os here when
  // the agent grows proxy support — one object, both launch paths inherit it.
} as const;

/**
 * Firefox prefs layered on top of Camoufox's fingerprint prefs to cut per-browser
 * memory. Merged AFTER camoufox-js output so these win; every key here is
 * process-topology / caching only — none are observable from page JS, so they do
 * not weaken the fingerprint.
 *
 * Why: in the sandbox each endpoint drives ~one page at a time, but Firefox's
 * Fission (per-origin site isolation) + default content-process pool fan a single
 * browser out to ~6 content processes (~4 GB across 8 browsers, measured live).
 * Site isolation is a defense for untrusted multi-origin browsing — irrelevant for
 * a single-purpose recon driver — so collapsing it to one content process reclaims
 * ~3 GB with no loss of capability. The rest drop caches a throwaway browser never
 * reuses.
 */
export const MEMORY_FIREFOX_PREFS: Record<string, unknown> = {
  "fission.autostart": false, // no per-origin site isolation → no process-per-origin fan-out
  "dom.ipc.processCount": 1, // single content-process pool
  "dom.ipc.processPrelaunch.enabled": false, // don't keep a spare content process warm
  "browser.cache.disk.enable": false, // throwaway profile: never persists a cache
  "browser.cache.memory.enable": false,
  "browser.sessionhistory.max_total_viewers": 0, // disable bfcache page retention
};

/**
 * Display-tier viewport geometry for headed Camoufox.
 *
 * Console's per-endpoint desktops (`packages/agents/desktopSession.ts`) and the
 * agent-image Xvfb shim (`packages/cluster-services/gen-purpose/desktop/Xvfb`)
 * use `DISPLAY_BASE = 10`: displays `:0`–`:9` are the shared computer-use
 * desktop at 1920x1080; `:10+` are per-endpoint desktops at 1280x720 (memory
 * cap under concurrency). Keep these in sync — a mismatch makes the browser
 * overflow/letterbox on the streamed desktop.
 */
export const ENDPOINT_DISPLAY_BASE = 10;
export const COMPUTER_USE_VIEWPORT_SIZE = "1920,1080";
export const ENDPOINT_VIEWPORT_SIZE = "1280,720";

/** Parse `"WIDTH,HEIGHT"` into a Camoufox `window` tuple; undefined if invalid. */
export function parseViewportSize(
  viewportSize: string,
): [number, number] | undefined {
  const match = /^(\d+),(\d+)$/.exec(viewportSize.trim());
  if (!match) return undefined;
  const width = Number(match[1]);
  const height = Number(match[2]);
  if (
    !Number.isFinite(width) ||
    !Number.isFinite(height) ||
    width <= 0 ||
    height <= 0
  ) {
    return undefined;
  }
  return [width, height];
}

/** Parse `":N"` / `":N.0"` display strings into N; undefined if unparseable. */
export function parseDisplayNumber(
  display: string | undefined,
): number | undefined {
  if (!display) return undefined;
  const match = /^:(\d+)/.exec(display.trim());
  if (!match) return undefined;
  const num = Number(match[1]);
  return Number.isFinite(num) ? num : undefined;
}

/**
 * Default viewport for a bound X display. Endpoint desktops (`:10+`) are 720p;
 * everything else (including no display / headless) stays at 1080p.
 */
export function viewportSizeForDisplay(display: string | undefined): string {
  const num = parseDisplayNumber(display);
  if (num !== undefined && num >= ENDPOINT_DISPLAY_BASE) {
    return ENDPOINT_VIEWPORT_SIZE;
  }
  return COMPUTER_USE_VIEWPORT_SIZE;
}

/**
 * Camoufox `window` + a `screen` floor (min only, never an exact pin).
 *
 * browserforge has no Firefox fingerprint at 720px height, so exact-pinning the
 * 720p endpoint tier made header generation throw for every browser call. A
 * min-only floor keeps `screen >= window` while staying in a covered bucket.
 */
export function camoufoxWindowOptions(window: [number, number]): {
  window: [number, number];
  screen: { minWidth: number; minHeight: number };
} {
  const [width, height] = window;
  return {
    window: [width, height],
    screen: { minWidth: width, minHeight: height },
  };
}

/** What camoufox-js `launchOptions()` returns: Playwright-firefox launch opts. */
export interface CamoufoxLaunchOptions {
  executablePath: string;
  args: string[];
  env: Record<string, string | number | boolean>;
  firefoxUserPrefs: Record<string, unknown>;
  headless: boolean;
  proxy?: {
    server: string;
    username?: string;
    password?: string;
    bypass?: string;
  };
}

export interface ResolveCamoufoxLaunchOptionsOpts {
  /** Fixed browser window size — must match the Xvfb geometry when headed. */
  readonly window?: [number, number];
}

/**
 * Resolve Playwright-firefox launch options for the host (MCP) path.
 * `headless` is a plain boolean here — the host runtime has no virtual display,
 * and Camoufox's fingerprint spoofing applies in headless mode regardless.
 */
export async function resolveCamoufoxLaunchOptions(
  headless: boolean,
  opts?: ResolveCamoufoxLaunchOptionsOpts,
): Promise<CamoufoxLaunchOptions> {
  // Loaded lazily (and kept external from the bundle) so the CLI's startup
  // commands (--version/--help) don't pull camoufox-js + its data-file deps
  // (fingerprint-generator/territoryInfo.xml) at module load.
  const { launchOptions: camoufoxLaunchOptions } = await import("camoufox-js");
  const windowOpts = opts?.window ? camoufoxWindowOptions(opts.window) : {};
  const resolved = (await camoufoxLaunchOptions({
    ...CAMOUFOX_OPTIONS,
    headless,
    ...windowOpts,
  })) as CamoufoxLaunchOptions;
  // Layer our memory prefs over Camoufox's fingerprint prefs (ours win).
  resolved.firefoxUserPrefs = {
    ...resolved.firefoxUserPrefs,
    ...MEMORY_FIREFOX_PREFS,
  };
  return resolved;
}

let ensurePromise: Promise<void> | null = null;

/**
 * Ensure the Camoufox browser build is downloaded.
 *
 * `launchOptions()` throws `CamoufoxNotInstalled` rather than downloading
 * synchronously, so we provision it lazily on first browser use — idempotent
 * and fast once the ~150 MB build is cached. Mirrors the sandbox's on-demand
 * install. Bake `npx camoufox-js fetch` into the runtime image to skip this.
 */
export function ensureCamoufox(log?: (msg: string) => void): Promise<void> {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      log?.(
        "Provisioning Camoufox browser (first run downloads ~150MB; cached after)…",
      );
      const require_ = createRequire(import.meta.url);
      const pkgPath = require_.resolve("camoufox-js/package.json");
      const fetchBin = join(dirname(pkgPath), "dist", "__main__.js");
      await execFileAsync("node", [fetchBin, "fetch"], {
        timeout: 5 * 60_000,
      });
    })().catch((err) => {
      ensurePromise = null; // let the next browser call retry
      throw err;
    });
  }
  return ensurePromise;
}
