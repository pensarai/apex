/**
 * Sandbox Playwright install helpers.
 *
 * Historically this file also defined a "launch-Chromium-per-tool-call"
 * tool factory (`createSandboxBrowserTools`) that ran a fresh Node.js
 * script on every browser_* invocation. That model was deleted in
 * favour of the persistent-daemon architecture — see
 * `./sandboxPlaywrightClient.ts` + `./sandbox-pw-daemon/daemon.cjs` +
 * `./sandboxPlaywrightDaemonTools.ts`.
 *
 * What remains: check / install Playwright + Chromium inside the
 * sandbox so the daemon can `require('playwright')` when it boots.
 * This is unchanged from the per-call era and continues to work with
 * both image-baked installs (Daytona snapshot via
 * `createSandbox({ installPlaywright: true })`) and cold-install
 * fallback.
 */

import type { UnifiedSandbox } from "./sandbox";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SANDBOX_PW_DIR = "/opt/sandbox-playwright";

// ---------------------------------------------------------------------------
// Installation check / install
// ---------------------------------------------------------------------------

/**
 * Per-sandbox installation promise cache. Prevents duplicate installs when
 * multiple daemon-boot paths fire concurrently on the same sandbox.
 */
const installationCache = new WeakMap<UnifiedSandbox, Promise<void>>();

/**
 * Check whether the `playwright` package is importable inside the sandbox.
 */
export async function checkSandboxPlaywright(
  sandbox: UnifiedSandbox,
): Promise<boolean> {
  // Write the check script inside the PW dir so require() can resolve
  // node_modules relative to the script's __dirname.
  const script = `try{require("playwright");console.log("OK")}catch(e){process.exit(1)}`;
  const b64 = Buffer.from(script).toString("base64");
  await sandbox.execute(
    `mkdir -p ${SANDBOX_PW_DIR} && echo "${b64}" | base64 -d > ${SANDBOX_PW_DIR}/pw_check.js`,
    { timeout: 10 },
  );
  const result = await sandbox.execute(`node ${SANDBOX_PW_DIR}/pw_check.js`, {
    timeout: 30,
  });
  return result.success && result.stdout.includes("OK");
}

/**
 * Install Playwright and the Chromium browser inside the sandbox.
 *
 * When Playwright + Chromium have already been baked into the Daytona image
 * snapshot (via `createSandbox({ installPlaywright: true })`), this function
 * is never called because {@link checkSandboxPlaywright} will return `true`
 * and {@link ensureSandboxPlaywright} will skip it.
 *
 * As a fallback this handles both Alpine (system Chromium via `apk`) and
 * Debian (Playwright's own installer).
 */
export async function installSandboxPlaywright(
  sandbox: UnifiedSandbox,
): Promise<void> {
  await sandbox.execute(`mkdir -p ${SANDBOX_PW_DIR}`, { timeout: 10 });

  const isAlpine = (await sandbox.execute("which apk", { timeout: 5 })).success;

  const initResult = await sandbox.execute(
    `cd ${SANDBOX_PW_DIR} && npm init -y --silent 2>/dev/null`,
    { timeout: 30 },
  );
  if (!initResult.success) {
    throw new Error(
      `Failed to init npm project in sandbox: ${initResult.stderr || initResult.stdout}`,
    );
  }

  // On Alpine, skip Playwright's bundled browser download — we install
  // system Chromium via apk instead.
  const npmInstallCmd = isAlpine
    ? `cd ${SANDBOX_PW_DIR} && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install playwright 2>&1`
    : `cd ${SANDBOX_PW_DIR} && npm install playwright 2>&1`;

  const installResult = await sandbox.execute(npmInstallCmd, { timeout: 300 });
  if (!installResult.success) {
    throw new Error(
      `Failed to install Playwright in sandbox: ${installResult.stderr || installResult.stdout}`,
    );
  }

  if (isAlpine) {
    const apkResult = await sandbox.execute(
      "apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont 2>&1",
      { timeout: 120 },
    );
    if (!apkResult.success) {
      throw new Error(
        `Failed to install Chromium via apk: ${apkResult.stderr || apkResult.stdout}`,
      );
    }
  } else {
    // Debian/Ubuntu: use Playwright's own installer.
    // Remove broken Yarn apt repo before installing system deps.
    await sandbox.execute(
      `(sudo rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.sources 2>/dev/null || rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.sources 2>/dev/null || true)`,
      { timeout: 10 },
    );

    let browserResult;
    for (let attempt = 1; attempt <= 3; attempt++) {
      browserResult = await sandbox.execute(
        `cd ${SANDBOX_PW_DIR} && npx playwright install chromium --with-deps 2>&1`,
        { timeout: 300 },
      );
      if (browserResult.success) break;
      if (attempt < 3) {
        await new Promise((r) => setTimeout(r, 3000));
      }
    }
    if (!browserResult!.success) {
      throw new Error(
        `Failed to install Chromium in sandbox: ${browserResult!.stderr || browserResult!.stdout}`,
      );
    }
  }
}

/**
 * Ensure Playwright is available in the sandbox, installing on-demand if
 * needed. The result is cached per-sandbox so repeated calls are free.
 */
export async function ensureSandboxPlaywright(
  sandbox: UnifiedSandbox,
): Promise<void> {
  let cached = installationCache.get(sandbox);
  if (cached) return cached;

  cached = (async () => {
    const installed = await checkSandboxPlaywright(sandbox);
    if (!installed) {
      await installSandboxPlaywright(sandbox);
    }
  })();

  installationCache.set(sandbox, cached);

  try {
    await cached;
  } catch (error) {
    installationCache.delete(sandbox);
    throw error;
  }
}
