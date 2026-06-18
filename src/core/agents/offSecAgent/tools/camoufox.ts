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
import { promisify } from "node:util";
import { launchOptions as camoufoxLaunchOptions } from "camoufox-js";

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

/** What camoufox-js `launchOptions()` returns: Playwright-firefox launch opts. */
export interface CamoufoxLaunchOptions {
  executablePath: string;
  args: string[];
  env: Record<string, string | number | boolean>;
  firefoxUserPrefs: Record<string, unknown>;
  headless: boolean;
  proxy?: { server: string; username?: string; password?: string; bypass?: string };
}

/**
 * Resolve Playwright-firefox launch options for the host (MCP) path.
 * `headless` is a plain boolean here — the host runtime has no virtual display,
 * and Camoufox's fingerprint spoofing applies in headless mode regardless.
 */
export async function resolveCamoufoxLaunchOptions(
  headless: boolean,
): Promise<CamoufoxLaunchOptions> {
  return (await camoufoxLaunchOptions({
    ...CAMOUFOX_OPTIONS,
    headless,
  })) as CamoufoxLaunchOptions;
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
      await execFileAsync("npx", ["--yes", "camoufox-js", "fetch"], {
        timeout: 5 * 60_000,
      });
    })().catch((err) => {
      ensurePromise = null; // let the next browser call retry
      throw err;
    });
  }
  return ensurePromise;
}
