/**
 * Sandbox Playwright Browser Tools
 *
 * When running in a sandbox environment, browser tools use Playwright directly
 * via {@link UnifiedSandbox.execute} instead of the local MCP server. This
 * avoids the need for MCP plumbing in the sandbox — Playwright scripts are
 * written to the sandbox filesystem, executed with Node.js, and results are
 * parsed from stdout.
 *
 * Architecture:
 *   1. On first browser tool call, check/install camoufox-js + Camoufox in the sandbox.
 *   2. Each tool call writes a short Node.js script that launches a persistent
 *      Camoufox (Firefox) context, performs the action, and prints a JSON
 *      result to stdout. State persists via the shared user-data dir.
 *   3. The host parses the JSON result and returns it to the agent.
 *
 * Browser state (pages, cookies, localStorage) persists across tool calls
 * because the Chromium process stays alive between connections.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../../http/targetHeaders";
import {
  defaultPolicy,
  type ToolPolicy,
  ToolPolicyDeniedError,
} from "../../../tools/backends/policy";
import type {
  BrowserBackend,
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserCookiesResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
  BrowserSnapshotResult,
} from "../../../tools/backends/types";
import {
  CAMOUFOX_OPTIONS,
  COMPUTER_USE_VIEWPORT_SIZE,
  ENDPOINT_DISPLAY_BASE,
  ENDPOINT_VIEWPORT_SIZE,
  MEMORY_FIREFOX_PREFS,
  parseViewportSize,
} from "./camoufox";
import type { SandboxExecutionResult, UnifiedSandbox } from "./sandbox";
import { resolverSessionFromCtx } from "./scopeGuard";
import type { ToolContext } from "./types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SANDBOX_PW_DIR = "/opt/sandbox-playwright";
const SANDBOX_EVIDENCE_DIR = "/tmp/evidence";
const SANDBOX_REFS_FILE = "/tmp/pw-refs.json";
const SANDBOX_URL_FILE = "/tmp/pw-current-url";
const SANDBOX_CONSOLE_FILE = "/tmp/pw-console-log.json";
const SANDBOX_CAMOU_CACHE = "/tmp/pw-camou-opts.json";

/** Marker pair used to extract JSON results from script stdout. */
const RESULT_START = "__PW_RESULT__";
const RESULT_END = "__PW_END__";

// ---------------------------------------------------------------------------
// Installation check / install
// ---------------------------------------------------------------------------

/**
 * Per-sandbox installation promise cache. Prevents duplicate installs when
 * multiple browser tools fire concurrently on the same sandbox.
 */
const installationCache = new WeakMap<UnifiedSandbox, Promise<void>>();

/**
 * Per-sandbox browser-setup promise cache. Prevents duplicate (destructive)
 * profile resets when multiple tool factories share the same sandbox — e.g.
 * a parent orchestrator and its spawned workers.
 */
const browserSetupCache = new WeakMap<UnifiedSandbox, Promise<void>>();

/**
 * Check whether camoufox-js, playwright-core, **and** the Camoufox browser
 * binary are all present inside the sandbox. Without the binary check,
 * a snapshot that has the JS deps but no fetched build would pass, causing
 * `ensureSandboxPlaywright` to skip `installSandboxPlaywright` (and its
 * fetch step) — then `launchOptions()` would fail at first use.
 */
export async function checkSandboxPlaywright(
  sandbox: UnifiedSandbox,
): Promise<boolean> {
  // camoufox-js is ESM-only — require() throws ERR_REQUIRE_ESM on Node < 20.19,
  // so probe it with dynamic import() (works on every Node version).
  // launchPath() returns the Camoufox binary path; existsSync confirms the
  // actual file was fetched (not just the npm package installed).
  const script = `(async()=>{try{const{launchPath}=await import("camoufox-js/dist/pkgman.js");require("playwright-core");if(!require("fs").existsSync(launchPath()))process.exit(1);console.log("OK")}catch(e){process.exit(1)}})()`;
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
 * Install camoufox-js (+ playwright-core) and download the Camoufox browser
 * build inside the sandbox.
 *
 * When these have already been baked into the Daytona image snapshot, this
 * function is never called because {@link checkSandboxPlaywright} returns
 * `true` and {@link ensureSandboxPlaywright} skips it.
 *
 * Camoufox ships glibc-linked Firefox builds, so the sandbox image must be
 * glibc-based (Debian/Ubuntu). Alpine/musl is unsupported and fails loudly
 * rather than silently falling back to a detectable browser.
 */
export async function installSandboxPlaywright(
  sandbox: UnifiedSandbox,
): Promise<void> {
  await sandbox.execute(`mkdir -p ${SANDBOX_PW_DIR}`, { timeout: 10 });

  const isAlpine = (await sandbox.execute("which apk", { timeout: 5 })).success;
  if (isAlpine) {
    throw new Error(
      "Camoufox requires a glibc-based sandbox image (Debian/Ubuntu); Alpine/musl is unsupported.",
    );
  }

  const initResult = await sandbox.execute(
    `cd ${SANDBOX_PW_DIR} && npm init -y --silent 2>/dev/null`,
    { timeout: 30 },
  );
  if (!initResult.success) {
    throw new Error(
      `Failed to init npm project in sandbox: ${initResult.stderr || initResult.stdout}`,
    );
  }

  // camoufox-js pulls in playwright-core, so a single install covers both the
  // launcher and the Playwright API the generated scripts use.
  const installResult = await sandbox.execute(
    `cd ${SANDBOX_PW_DIR} && npm install camoufox-js@0.11.1 playwright-core@1.53.1 2>&1`,
    { timeout: 300 },
  );
  if (!installResult.success) {
    throw new Error(
      `Failed to install camoufox-js in sandbox: ${installResult.stderr || installResult.stdout}`,
    );
  }

  // Camoufox is a patched Firefox — install the GTK/nss/font/X11 system
  // libraries that Firefox (even headless) requires. Playwright's
  // `install-deps firefox` handles the right apt packages for the distro.
  // The Yarn apt repo ships a stale GPG key that makes `apt-get update` fail on
  // many images, so remove it first (we don't need Yarn here). Drop both the
  // legacy one-line list and the newer deb822 `.sources` entry — images ship
  // one or the other. We run as root in the sandbox (apt needs it anyway), so
  // plain rm suffices.
  const depsResult = await sandbox.execute(
    `rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.sources 2>/dev/null; cd ${SANDBOX_PW_DIR} && npx playwright@1.53.1 install-deps firefox 2>&1`,
    { timeout: 300 },
  );
  if (!depsResult.success) {
    // Fail loudly here — otherwise the missing libraries only surface later as
    // a cryptic Camoufox launch crash (checkSandboxPlaywright only verifies JS
    // imports, not the native deps).
    throw new Error(
      `Failed to install Firefox system deps in sandbox: ${depsResult.stderr || depsResult.stdout}`,
    );
  }

  // Download the Camoufox browser build (cached under CAMOUFOX_INSTALL_DIR /
  // ~/.cache). Uses the locally-installed binary so the fetched build matches
  // the pinned camoufox-js version (npx could pull a different one).
  let fetchResult: SandboxExecutionResult | undefined;
  for (let attempt = 1; attempt <= 3; attempt++) {
    fetchResult = await sandbox.execute(
      `cd ${SANDBOX_PW_DIR} && node ./node_modules/camoufox-js/dist/__main__.js fetch 2>&1`,
      { timeout: 300 },
    );
    if (fetchResult.success) break;
    if (attempt < 3) {
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  if (!fetchResult!.success) {
    throw new Error(
      `Failed to fetch Camoufox in sandbox: ${fetchResult!.stderr || fetchResult!.stdout}`,
    );
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

// ---------------------------------------------------------------------------
// Browser lifecycle
// ---------------------------------------------------------------------------

/**
 * Verify that Playwright can launch Chromium in the sandbox.
 * This is a lightweight smoke-test — the actual browser is launched per-script
 * via `launchPersistentContext` so no long-running process is needed.
 */
export async function ensureSandboxBrowser(
  sandbox: UnifiedSandbox,
): Promise<void> {
  // Reset the per-session browser identity so a reused sandbox doesn't carry
  // over the previous session's state. Clear the cached Camoufox options (the
  // frozen fingerprint + headless flag) AND the persistent profile dir
  // (cookies/localStorage/nav) together — clearing only the fingerprint would
  // launch a fresh fingerprint against a stale profile, which both leaks
  // cross-session state and is itself a detection tell.
  await sandbox.execute(
    `rm -rf /tmp/pw-user-data ${SANDBOX_CAMOU_CACHE}; mkdir -p ${SANDBOX_EVIDENCE_DIR} /tmp/pw-user-data`,
    { timeout: 5 },
  );
}

/**
 * Full setup: install Playwright if needed, then prepare directories.
 * Browser reset is cached per sandbox so spawned workers don't wipe
 * cookies/profile data established by the parent or earlier workers.
 */
async function ensureSandboxReady(sandbox: UnifiedSandbox): Promise<void> {
  await ensureSandboxPlaywright(sandbox);

  let cached = browserSetupCache.get(sandbox);
  if (!cached) {
    cached = ensureSandboxBrowser(sandbox);
    browserSetupCache.set(sandbox, cached);
    try {
      await cached;
    } catch (error) {
      browserSetupCache.delete(sandbox);
      throw error;
    }
  } else {
    await cached;
  }
}

// ---------------------------------------------------------------------------
// Script execution helper
// ---------------------------------------------------------------------------

/**
 * Write a Playwright Node.js script to the sandbox, execute it, and parse
 * the JSON result from between the {@link RESULT_START}/{@link RESULT_END}
 * markers in stdout.
 *
 * Each script launches a persistent browser context (with a shared user-data
 * dir) so that cookies, localStorage, and other state survive across calls.
 * The browser is closed when the script exits.
 *
 * @param sandbox  - The sandbox to execute in
 * @param body     - The *body* of the async IIFE. Has `context` and `page`
 *                   in scope. Must call `resolve(jsonValue)` to return a result.
 * @param timeout  - Sandbox execution timeout in seconds (default 60)
 */
async function runPlaywrightScript(
  sandbox: UnifiedSandbox,
  body: string,
  timeout = 60,
  extraHttpHeaders?: Record<string, string>,
): Promise<unknown> {
  const headersJson =
    extraHttpHeaders && Object.keys(extraHttpHeaders).length > 0
      ? JSON.stringify(extraHttpHeaders)
      : "null";
  const script = `
const { firefox } = require('playwright-core');
const fs = require('fs');

(async () => {
  const { launchOptions } = await import('camoufox-js');
  function resolve(value) {
    process.stdout.write('${RESULT_START}' + JSON.stringify(value) + '${RESULT_END}');
  }

  // Resolved per script invocation so /headers mutations take effect
  // on the next browser tool call.
  const __extraHeaders = ${headersJson};

  // Use the sandbox's virtual display if one is present — Camoufox is far less
  // detectable headful. Falls back to plain headless, which is still fully
  // fingerprint-spoofed (just a weaker stealth posture, never vanilla Chromium).
  const __headless = process.env.DISPLAY ? false : true;
  // Match Camoufox window to the bound Xvfb tier (Console desktopSession /
  // Xvfb shim: :0–:9 → 1920x1080, :10+ → 1280x720). Constants are inlined
  // from ./camoufox so host + sandbox stay lockstep.
  const __ENDPOINT_DISPLAY_BASE = ${ENDPOINT_DISPLAY_BASE};
  const __endpointWindow = ${JSON.stringify(parseViewportSize(ENDPOINT_VIEWPORT_SIZE))};
  const __computerUseWindow = ${JSON.stringify(parseViewportSize(COMPUTER_USE_VIEWPORT_SIZE))};
  const __displayMatch = /^:(\\d+)/.exec(process.env.DISPLAY || '');
  const __displayNum = __displayMatch ? Number(__displayMatch[1]) : undefined;
  const __window =
    __displayNum !== undefined && __displayNum >= __ENDPOINT_DISPLAY_BASE
      ? __endpointWindow
      : __computerUseWindow;
  // Resolve Camoufox options once per sandbox session and cache to disk so
  // every tool call presents the same fingerprint on the shared profile dir.
  let __camou;
  try {
    __camou = JSON.parse(fs.readFileSync('${SANDBOX_CAMOU_CACHE}', 'utf-8'));
  } catch {
    __camou = await launchOptions({
      ...${JSON.stringify(CAMOUFOX_OPTIONS)},
      headless: __headless,
      window: __window,
      // Floor only — exact-pinning a 720px height throws in browserforge.
      screen: { minWidth: __window[0], minHeight: __window[1] },
    });
    fs.writeFileSync('${SANDBOX_CAMOU_CACHE}', JSON.stringify(__camou));
  }

  let context;
  const __consoleMessages = [];
  try {
    context = await firefox.launchPersistentContext('/tmp/pw-user-data', {
      ...__camou,
      // Layer memory prefs over Camoufox's fingerprint prefs (ours win); see
      // MEMORY_FIREFOX_PREFS in ./camoufox — collapses Fission/content-process
      // fan-out that otherwise costs ~3 GB across the run.
      firefoxUserPrefs: { ...__camou.firefoxUserPrefs, ...${JSON.stringify(MEMORY_FIREFOX_PREFS)} },
      ...(__extraHeaders ? { extraHTTPHeaders: __extraHeaders } : {}),
    });
    const pages = context.pages();
    const page = pages.length > 0 ? pages[pages.length - 1] : await context.newPage();

    page.on('console', msg => {
      __consoleMessages.push({ type: msg.type(), text: msg.text() });
    });

    // Restore the last-visited URL so page state persists across tool calls.
    if (page.url() === 'about:blank') {
      try {
        const savedUrl = fs.readFileSync('${SANDBOX_URL_FILE}', 'utf-8').trim();
        if (savedUrl) await page.goto(savedUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });
      } catch {}
    }

    ${body}

  } catch (error) {
    resolve({ success: false, error: error.message || String(error) });
  } finally {
    if (__consoleMessages.length > 0) {
      try {
        const fs = require('fs');
        let existing = [];
        try { existing = JSON.parse(fs.readFileSync('${SANDBOX_CONSOLE_FILE}', 'utf-8')); } catch {}
        existing.push(...__consoleMessages);
        if (existing.length > 200) existing = existing.slice(-200);
        fs.writeFileSync('${SANDBOX_CONSOLE_FILE}', JSON.stringify(existing));
      } catch {}
    }
    // Tear the browser down so a wedged Camoufox can't orphan inside the
    // sandbox and accumulate across tool calls until it OOMs. context.close()
    // can hang on a stuck browser (same wedge class as the host MCP path), so
    // bound it, then SIGKILL any surviving descendant PIDs of this script — the
    // in-sandbox analog of collectDescendantPids() in playwrightMcp.ts. Only
    // this script's own children are touched, so it is safe under the parent +
    // worker concurrency that shares a sandbox.
    if (context) {
      let __closeTimer;
      await Promise.race([
        (async () => { try { await context.close(); } catch {} })(),
        new Promise((r) => { __closeTimer = setTimeout(r, 8000); }),
      ]);
      if (__closeTimer) clearTimeout(__closeTimer);
    }
    try {
      if (fs.existsSync('/proc')) {
        const __childrenByPpid = new Map();
        for (const __name of fs.readdirSync('/proc')) {
          if (!/^[0-9]+$/.test(__name)) continue;
          try {
            const __stat = fs.readFileSync('/proc/' + __name + '/stat', 'utf8');
            const __ppid = Number(__stat.slice(__stat.lastIndexOf(')') + 2).split(' ')[1]);
            if (!Number.isFinite(__ppid)) continue;
            if (!__childrenByPpid.has(__ppid)) __childrenByPpid.set(__ppid, []);
            __childrenByPpid.get(__ppid).push(Number(__name));
          } catch {}
        }
        const __doomed = [];
        const __seen = new Set([process.pid]);
        const __stack = [process.pid];
        while (__stack.length) {
          const __p = __stack.pop();
          for (const __c of (__childrenByPpid.get(__p) || [])) {
            if (__seen.has(__c)) continue;
            __seen.add(__c); __doomed.push(__c); __stack.push(__c);
          }
        }
        for (const __p of __doomed) { try { process.kill(__p, 'SIGKILL'); } catch {} }
      }
    } catch {}
  }
})();
`;

  const b64 = Buffer.from(script).toString("base64");
  const result = await sandbox.execute(
    `echo "${b64}" | base64 -d > ${SANDBOX_PW_DIR}/pw_action.js && node ${SANDBOX_PW_DIR}/pw_action.js`,
    { timeout },
  );

  const stdout = result.stdout || "";
  const match = stdout.match(
    new RegExp(
      `${RESULT_START.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([\\s\\S]*?)${RESULT_END.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`,
    ),
  );

  if (!match) {
    if (!result.success) {
      throw new Error(
        `Playwright script failed: ${result.stderr || stdout || "unknown error"}`,
      );
    }
    throw new Error(
      `No result marker in script output: ${stdout.substring(0, 500)}`,
    );
  }

  try {
    return JSON.parse(match[1]);
  } catch {
    return match[1];
  }
}

// ---------------------------------------------------------------------------
// Sandbox browser backend
// ---------------------------------------------------------------------------

async function checkPolicy(
  policy: ToolPolicy,
  ctx: ToolContext,
  op: string,
  args: unknown,
): Promise<void> {
  const decision = await policy.beforeCall({
    backend: "browser",
    op,
    args,
    ctx,
  });
  if (!decision.allow) {
    throw new ToolPolicyDeniedError("browser", op, decision.reason);
  }
}

/**
 * The {@link BrowserBackend} implementation for a {@link UnifiedSandbox}:
 * browser tool calls run inside the sandbox via direct Playwright execution
 * (no MCP). Playwright and Chromium are installed on-demand in the sandbox on
 * the first call.
 *
 * The setup gate and script queue are scoped to the returned object, so a
 * host composing `ToolBackends` must build one instance per session/lease and
 * reuse it across calls — matching how `LocalBackends` memoizes its browser
 * session.
 */
export function SandboxBrowserBackend(
  ctx: ToolContext,
  policy: ToolPolicy = defaultPolicy,
): BrowserBackend {
  const sandbox = ctx.sandbox!;
  const evidenceDir = join(ctx.session.rootPath, "evidence");
  const targetUrl = ctx.target ?? "";

  if (!existsSync(evidenceDir)) {
    mkdirSync(evidenceDir, { recursive: true });
  }

  // Shared setup gate — only runs once per sandbox.
  let setupPromise: Promise<void> | null = null;
  function setup(): Promise<void> {
    if (!setupPromise) {
      setupPromise = ensureSandboxReady(sandbox);
    }
    return setupPromise;
  }

  // Serialise sandbox script execution so concurrent tool calls don't race on
  // the shared Camoufox fingerprint cache or the persistent browser profile dir.
  let scriptQueue: Promise<unknown> = Promise.resolve();

  function runScript(body: string, timeout = 60): Promise<unknown> {
    const resolved = targetUrl
      ? resolveEffectiveHeaders(resolverSessionFromCtx(ctx), targetUrl)
      : ctx.session.config?.headers;
    const headers = stripBrowserManagedHeaders(resolved);
    const next = scriptQueue.then(() =>
      runPlaywrightScript(sandbox, body, timeout, headers),
    );
    scriptQueue = next.then(
      () => {},
      () => {},
    );
    return next;
  }

  // ------- navigate -----------------------------------------------------

  async function navigate(url: string): Promise<BrowserNavigateResult> {
    await checkPolicy(policy, ctx, "navigate", { url });
    try {
      await setup();
      const result = (await runScript(
        `
    await page.goto(${JSON.stringify(url)}, { waitUntil: 'domcontentloaded', timeout: 30000 });
    // Persist current URL so subsequent tool calls can restore the page
    require('fs').writeFileSync('${SANDBOX_URL_FILE}', page.url());
    const title = await page.title();

    resolve({ success: true, url: page.url(), title });
        `,
        60,
      )) as BrowserNavigateResult;
      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, url, error: message };
    }
  }

  // ------- screenshot -----------------------------------------------------

  async function screenshot(o: {
    filename: string;
  }): Promise<BrowserScreenshotResult> {
    await checkPolicy(policy, ctx, "screenshot", o);
    try {
      await setup();
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const screenshotFilename = `${o.filename}_${timestamp}.png`;
      const sandboxPath = `${SANDBOX_EVIDENCE_DIR}/${screenshotFilename}`;

      const result = (await runScript(
        `
    const buf = await page.screenshot({ fullPage: false });
    const b64 = buf.toString('base64');
    require('fs').mkdirSync(${JSON.stringify(SANDBOX_EVIDENCE_DIR)}, { recursive: true });
    require('fs').writeFileSync(${JSON.stringify(sandboxPath)}, buf);
    resolve({ success: true, data: b64, sandboxPath: ${JSON.stringify(sandboxPath)} });
        `,
        30,
      )) as {
        success: boolean;
        data?: string;
        sandboxPath?: string;
        error?: string;
      };

      if (result.success && result.data) {
        const localPath = join(evidenceDir, screenshotFilename);
        const dir = dirname(localPath);
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        writeFileSync(localPath, Buffer.from(result.data, "base64"));
        // The PNG bytes are already back on the host (via base64) and
        // written to `evidenceDir`; the sandbox-side staging copy in
        // `/tmp/evidence` is never read again. Drop it so a
        // screenshot-heavy scan doesn't accumulate them until teardown
        // (ENOSPC). Best-effort — a failed cleanup must not fail the tool.
        void sandbox
          .execute(`rm -f ${sandboxPath}`, { timeout: 10 })
          .catch(() => {});
        return {
          success: true,
          path: localPath,
          message: `Screenshot saved to ${localPath}`,
        };
      }

      return { success: false, error: result.error || "No screenshot data" };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ------- snapshot -----------------------------------------------------

  async function snapshot(): Promise<BrowserSnapshotResult> {
    await checkPolicy(policy, ctx, "snapshot", {});
    try {
      await setup();
      const result = (await runScript(
        `
    // Build accessibility snapshot via page.evaluate — works on all
    // Playwright versions and doesn't depend on the deprecated
    // page.accessibility.snapshot() API.
    const treeData = await page.evaluate(() => {
      function tagToAriaRole(el) {
        const tag = el.tagName.toLowerCase();
        switch (tag) {
          case 'a': return el.hasAttribute('href') ? 'link' : 'generic';
          case 'button': return 'button';
          case 'input': {
            const t = (el.getAttribute('type') || 'text').toLowerCase();
            if (t === 'button' || t === 'submit' || t === 'reset' || t === 'image') return 'button';
            if (t === 'checkbox') return 'checkbox';
            if (t === 'radio') return 'radio';
            if (t === 'range') return 'slider';
            if (t === 'number') return 'spinbutton';
            if (t === 'search') return 'searchbox';
            return 'textbox';
          }
          case 'select': return el.hasAttribute('multiple') ? 'listbox' : 'combobox';
          case 'textarea': return 'textbox';
          case 'img': return 'img';
          case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6': return 'heading';
          case 'table': return 'table';
          case 'form': return 'form';
          case 'nav': return 'navigation';
          case 'main': return 'main';
          case 'header': return 'banner';
          case 'footer': return 'contentinfo';
          case 'aside': return 'complementary';
          case 'article': return 'article';
          case 'ul': case 'ol': return 'list';
          case 'li': return 'listitem';
          case 'dialog': return 'dialog';
          case 'progress': return 'progressbar';
          case 'option': return 'option';
          case 'fieldset': return 'group';
          case 'output': return 'status';
          default: return tag;
        }
      }
      function walk(el, depth) {
        const role = el.getAttribute('role') || tagToAriaRole(el);
        const name = el.getAttribute('aria-label')
          || el.getAttribute('name')
          || el.getAttribute('placeholder')
          || (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' ? el.getAttribute('type') || '' : '')
          || el.textContent?.trim().substring(0, 60) || '';
        const value = el.value !== undefined && el.value !== '' ? el.value : undefined;
        const children = [];
        for (const child of el.children) {
          children.push(walk(child, depth + 1));
        }
        return { role, name, value, children, depth };
      }
      return walk(document.body, 0);
    });

    const refMap = {};
    let refId = 0;

    function formatNode(node, depth) {
      if (!node) return '';
      const ref = 'e' + (refId++);
      const lines = [];
      const indent = '  '.repeat(depth);
      let desc = indent + '[ref=' + ref + '] ' + (node.role || 'unknown');
      if (node.name) desc += ' "' + node.name.substring(0, 80) + '"';
      if (node.value) desc += ' value="' + String(node.value).substring(0, 40) + '"';
      lines.push(desc);

      refMap[ref] = { role: node.role, name: node.name || '' };

      if (node.children) {
        for (const child of node.children) {
          const childText = formatNode(child, depth + 1);
          if (childText) lines.push(childText);
        }
      }
      return lines.join('\\n');
    }

    const text = formatNode(treeData, 0);
    require('fs').writeFileSync(${JSON.stringify(SANDBOX_REFS_FILE)}, JSON.stringify(refMap));
    resolve({ success: true, snapshot: text });
        `,
        30,
      )) as { success: boolean; snapshot?: string; error?: string };

      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ------- click -----------------------------------------------------

  async function click(o: {
    element: string;
    ref?: string;
  }): Promise<BrowserClickResult> {
    await checkPolicy(policy, ctx, "click", o);
    const { element, ref } = o;
    try {
      await setup();
      const result = (await runScript(
        `
    const ref = ${JSON.stringify(ref || "")};
    const element = ${JSON.stringify(element)};

    const TAG_TO_ROLE = {
      a:'link',input:'textbox',select:'combobox',textarea:'textbox',
      img:'img',h1:'heading',h2:'heading',h3:'heading',h4:'heading',
      h5:'heading',h6:'heading',nav:'navigation',main:'main',
      header:'banner',footer:'contentinfo',aside:'complementary',
      article:'article',ul:'list',ol:'list',li:'listitem',
      dialog:'dialog',progress:'progressbar',option:'option',
      fieldset:'group',output:'status',button:'button',form:'form',table:'table'
    };

    if (ref) {
      try {
        const refData = JSON.parse(require('fs').readFileSync(${JSON.stringify(SANDBOX_REFS_FILE)}, 'utf-8'));
        const info = refData[ref];
        if (info && info.role && info.name) {
          const role = TAG_TO_ROLE[info.role] || info.role;
          await page.getByRole(role, { name: info.name }).first().click({ timeout: 10000 });
          resolve({ success: true, element, result: 'Clicked via ref ' + ref });
          return;
        }
      } catch {}
    }

    // Fallback: use text / role heuristic matching
    try {
      await page.getByRole('button', { name: element }).first().click({ timeout: 5000 });
      resolve({ success: true, element, result: 'Clicked button matching: ' + element });
      return;
    } catch {}

    try {
      await page.getByRole('link', { name: element }).first().click({ timeout: 5000 });
      resolve({ success: true, element, result: 'Clicked link matching: ' + element });
      return;
    } catch {}

    try {
      await page.getByText(element).first().click({ timeout: 5000 });
      resolve({ success: true, element, result: 'Clicked text matching: ' + element });
      return;
    } catch {}

    // Last resort: broad locator
    await page.locator('text=' + element).first().click({ timeout: 10000 });
    resolve({ success: true, element, result: 'Clicked via text locator: ' + element });
        `,
        30,
      )) as BrowserClickResult;

      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ------- fill -----------------------------------------------------

  async function fill(o: {
    element: string;
    ref?: string;
    value: string;
  }): Promise<BrowserFillResult> {
    await checkPolicy(policy, ctx, "fill", o);
    const { element, ref, value } = o;
    try {
      await setup();
      const result = (await runScript(
        `
    const ref = ${JSON.stringify(ref || "")};
    const element = ${JSON.stringify(element)};
    const value = ${JSON.stringify(value)};

    const TAG_TO_ROLE = {
      a:'link',input:'textbox',select:'combobox',textarea:'textbox',
      img:'img',h1:'heading',h2:'heading',h3:'heading',h4:'heading',
      h5:'heading',h6:'heading',nav:'navigation',main:'main',
      header:'banner',footer:'contentinfo',aside:'complementary',
      article:'article',ul:'list',ol:'list',li:'listitem',
      dialog:'dialog',progress:'progressbar',option:'option',
      fieldset:'group',output:'status',button:'button',form:'form',table:'table'
    };

    if (ref) {
      try {
        const refData = JSON.parse(require('fs').readFileSync(${JSON.stringify(SANDBOX_REFS_FILE)}, 'utf-8'));
        const info = refData[ref];
        if (info && info.role && info.name) {
          const role = TAG_TO_ROLE[info.role] || info.role;
          await page.getByRole(role, { name: info.name }).first().fill(value, { timeout: 10000 });
          resolve({ success: true, element, result: 'Filled via ref ' + ref });
          return;
        }
      } catch {}
    }

    // Fallback: try label, placeholder, or role matching
    try {
      await page.getByLabel(element).first().fill(value, { timeout: 5000 });
      resolve({ success: true, element, result: 'Filled by label: ' + element });
      return;
    } catch {}

    try {
      await page.getByPlaceholder(element).first().fill(value, { timeout: 5000 });
      resolve({ success: true, element, result: 'Filled by placeholder: ' + element });
      return;
    } catch {}

    try {
      await page.getByRole('textbox', { name: element }).first().fill(value, { timeout: 5000 });
      resolve({ success: true, element, result: 'Filled textbox matching: ' + element });
      return;
    } catch {}

    // Last resort
    await page.locator('[placeholder*="' + element.replace(/"/g, '') + '" i]').first().fill(value, { timeout: 10000 });
    resolve({ success: true, element, result: 'Filled via placeholder locator: ' + element });
        `,
        30,
      )) as BrowserFillResult;

      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ------- evaluate -----------------------------------------------------

  async function evaluate(o: {
    script: string;
  }): Promise<BrowserEvaluateResult> {
    await checkPolicy(policy, ctx, "evaluate", o);
    const { script } = o;
    try {
      await setup();

      const isFunction =
        /^\s*(async\s+)?\(/.test(script) ||
        /^\s*(async\s+)?function\s*\(/.test(script);
      const fnScript = isFunction ? script : `() => (${script})`;

      const result = (await runScript(
        `
    const fnStr = ${JSON.stringify(fnScript)};
    const fn = new Function('return (' + fnStr + ')')();
    const evalResult = await page.evaluate(fn);
    resolve({ success: true, script: ${JSON.stringify(script)}, result: evalResult });
        `,
        30,
      )) as BrowserEvaluateResult;

      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ------- console -----------------------------------------------------

  async function consoleMessages(): Promise<BrowserConsoleResult> {
    await checkPolicy(policy, ctx, "console", {});
    try {
      await setup();
      const result = (await runScript(
        `
    const fs = require('fs');
    let persisted = [];
    try { persisted = JSON.parse(fs.readFileSync('${SANDBOX_CONSOLE_FILE}', 'utf-8')); } catch {}
    const allMessages = [...persisted, ...__consoleMessages];
    try { fs.writeFileSync('${SANDBOX_CONSOLE_FILE}', '[]'); } catch {}
    __consoleMessages.length = 0;
    resolve({ success: true, messages: allMessages, result: allMessages });
        `,
        15,
      )) as BrowserConsoleResult;

      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ------- getCookies -----------------------------------------------------

  async function getCookies(o?: {
    urls?: string[];
  }): Promise<BrowserCookiesResult> {
    await checkPolicy(policy, ctx, "getCookies", o ?? {});
    try {
      await setup();
      const result = (await runScript(
        `
    const urls = ${JSON.stringify(o?.urls || [])};
    const cookies = urls.length > 0
      ? await context.cookies(urls)
      : await context.cookies();
    const cookieHeader = cookies.map(c => c.name + '=' + c.value).join('; ');
    resolve({ success: true, cookies, cookieHeader });
        `,
        15,
      )) as BrowserCookiesResult;

      return result;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  return {
    navigate,
    snapshot,
    screenshot,
    click,
    fill,
    evaluate,
    console: consoleMessages,
    getCookies,
  };
}
