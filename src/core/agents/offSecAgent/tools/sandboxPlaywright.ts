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
 *   1. On first browser tool call, check/install Playwright + Chromium in the sandbox.
 *   2. Launch a persistent headless Chromium via its CLI with `--remote-debugging-port`.
 *   3. Each tool call writes a short Node.js script that connects via CDP,
 *      performs the action, and prints a JSON result to stdout.
 *   4. The host parses the JSON result and returns it to the agent.
 *
 * Browser state (pages, cookies, localStorage) persists across tool calls
 * because the Chromium process stays alive between connections.
 */

import { tool } from "ai";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import {
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../../http/targetHeaders";
import type {
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
} from "./playwrightMcp";
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

    let browserResult: SandboxExecutionResult | undefined;
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
  await sandbox.execute(`mkdir -p ${SANDBOX_EVIDENCE_DIR} /tmp/pw-user-data`, {
    timeout: 5,
  });
}

/**
 * Full setup: install Playwright if needed, then prepare directories.
 */
async function ensureSandboxReady(sandbox: UnifiedSandbox): Promise<void> {
  await ensureSandboxPlaywright(sandbox);
  await ensureSandboxBrowser(sandbox);
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
const { chromium } = require('playwright');
const fs = require('node:fs');

(async () => {
  function resolve(value) {
    process.stdout.write('${RESULT_START}' + JSON.stringify(value) + '${RESULT_END}');
  }

  // Prefer system Chromium (Alpine apk install) over Playwright's bundled binary.
  let executablePath;
  for (const p of ['/usr/bin/chromium-browser', '/usr/bin/chromium']) {
    try { fs.accessSync(p, fs.constants.X_OK); executablePath = p; break; } catch {}
  }

  // Resolved per script invocation so /headers mutations take effect
  // on the next browser tool call.
  const __extraHeaders = ${headersJson};

  let context;
  const __consoleMessages = [];
  try {
    context = await chromium.launchPersistentContext('/tmp/pw-user-data', {
      headless: true,
      ...(executablePath ? { executablePath } : {}),
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
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
        const fs = require('node:fs');
        let existing = [];
        try { existing = JSON.parse(fs.readFileSync('${SANDBOX_CONSOLE_FILE}', 'utf-8')); } catch {}
        existing.push(...__consoleMessages);
        if (existing.length > 200) existing = existing.slice(-200);
        fs.writeFileSync('${SANDBOX_CONSOLE_FILE}', JSON.stringify(existing));
      } catch {}
    }
    if (context) {
      try { await context.close(); } catch {}
    }
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
// Input schemas (mirrors playwrightMcp.ts – kept local for decoupling)
// ---------------------------------------------------------------------------

const BrowserNavigateInput = z.object({
  url: z.string().describe("Full URL to navigate to"),
  toolCallDescription: z
    .string()
    .describe("Why you are navigating to this URL"),
});

const BrowserScreenshotInput = z.object({
  filename: z
    .string()
    .describe("Descriptive filename for screenshot (without extension)"),
  toolCallDescription: z
    .string()
    .describe("What evidence this screenshot captures"),
});

const BrowserSnapshotInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to get the page snapshot"),
});

const BrowserClickInput = z.object({
  element: z
    .string()
    .describe(
      "Description of element to click, e.g., 'Submit button' or 'Login link'",
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e5'). If provided, uses exact element reference for precise clicking.",
    ),
  toolCallDescription: z.string().describe("Why you are clicking this element"),
});

const BrowserFillInput = z.object({
  element: z
    .string()
    .describe(
      "Description of form field, e.g., 'Username field' or 'Search input'",
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e3'). If provided, uses exact element reference for precise filling.",
    ),
  value: z.string().describe("Value to fill into the field"),
  toolCallDescription: z
    .string()
    .describe("Why you are filling this field with this value"),
});

const BrowserEvaluateInput = z.object({
  script: z.string().describe("JavaScript code to execute in browser"),
  toolCallDescription: z
    .string()
    .describe("What you are testing with this script"),
});

const BrowserConsoleInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to check console messages"),
});

const BrowserGetCookiesInput = z.object({
  urls: z
    .array(z.string())
    .optional()
    .describe(
      "Optional list of URLs to get cookies for. If not provided, gets all cookies.",
    ),
  toolCallDescription: z
    .string()
    .describe("Why you need to extract cookies from the browser"),
});

// ---------------------------------------------------------------------------
// Sandbox browser tools factory
// ---------------------------------------------------------------------------

/**
 * Create the full set of browser tools that run inside a
 * {@link UnifiedSandbox} via direct Playwright execution (no MCP).
 *
 * The factory lazily installs Playwright and launches Chromium in the sandbox
 * on the first tool invocation.
 */
export function createSandboxBrowserTools(ctx: ToolContext) {
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

  // Resolve fresh on every tool call so /headers mutations apply next call.
  function runScript(body: string, timeout = 60): Promise<unknown> {
    const resolved = targetUrl
      ? resolveEffectiveHeaders(resolverSessionFromCtx(ctx), targetUrl)
      : ctx.session.config?.headers;
    return runPlaywrightScript(
      sandbox,
      body,
      timeout,
      stripBrowserManagedHeaders(resolved),
    );
  }

  // ------- browser_navigate -------------------------------------------------

  const browser_navigate = tool({
    description: `Navigate the browser to a URL to load and render a page.

Use this to load SPAs, JavaScript-heavy pages, or any page that requires full browser rendering.
The page will be fully loaded and JavaScript executed before returning.

Target base URL: ${targetUrl}`,
    inputSchema: BrowserNavigateInput,
    execute: async ({ url }): Promise<BrowserNavigateResult> => {
      try {
        await setup();
        const result = (await runScript(
          `
    await page.goto(${JSON.stringify(url)}, { waitUntil: 'domcontentloaded', timeout: 30000 });
    // Persist current URL so subsequent tool calls can restore the page
    require('node:fs').writeFileSync('${SANDBOX_URL_FILE}', page.url());
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
    },
  });

  // ------- browser_screenshot -----------------------------------------------

  const browser_screenshot = tool({
    description: `Take a screenshot of the current page for evidence/documentation.

Use this to document:
- Exposed admin panels or sensitive pages
- Interesting error pages or debug information
- Visual proof of discovered vulnerabilities
- Login pages and authentication flows`,
    inputSchema: BrowserScreenshotInput,
    execute: async ({ filename }): Promise<BrowserScreenshotResult> => {
      try {
        await setup();
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const screenshotFilename = `${filename}_${timestamp}.png`;
        const sandboxPath = `${SANDBOX_EVIDENCE_DIR}/${screenshotFilename}`;

        const result = (await runScript(
          `
    const buf = await page.screenshot({ fullPage: false });
    const b64 = buf.toString('base64');
    require('node:fs').mkdirSync(${JSON.stringify(SANDBOX_EVIDENCE_DIR)}, { recursive: true });
    require('node:fs').writeFileSync(${JSON.stringify(sandboxPath)}, buf);
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
    },
  });

  // ------- browser_snapshot -------------------------------------------------

  const browser_snapshot = tool({
    description: `Get the accessibility snapshot of the current page.

IMPORTANT: Call this BEFORE using browser_click or browser_fill to get element references (refs).
The snapshot returns an accessibility tree with elements marked like [ref=e5].
Use these refs in browser_click and browser_fill for precise element targeting.

Example workflow:
1. Call browser_snapshot to get the page structure
2. Find the element you need (e.g., "textbox 'Email'" with [ref=e3])
3. Call browser_fill with ref="e3" to fill that specific element`,
    inputSchema: BrowserSnapshotInput,
    execute: async (): Promise<{
      success: boolean;
      snapshot?: string;
      error?: string;
    }> => {
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
    require('node:fs').writeFileSync(${JSON.stringify(SANDBOX_REFS_FILE)}, JSON.stringify(refMap));
    resolve({ success: true, snapshot: text });
          `,
          30,
        )) as { success: boolean; snapshot?: string; error?: string };

        return result;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return { success: false, error: message };
      }
    },
  });

  // ------- browser_click ----------------------------------------------------

  const browser_click = tool({
    description: `Click on an element in the page by describing it.

Use this to:
- Navigate through multi-step flows
- Expand collapsed menus or sections
- Click buttons, links, or interactive elements
- Submit forms

IMPORTANT: For reliable clicking, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserClickInput,
    execute: async ({ element, ref }): Promise<BrowserClickResult> => {
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
        const refData = JSON.parse(require('node:fs').readFileSync(${JSON.stringify(SANDBOX_REFS_FILE)}, 'utf-8'));
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
    },
  });

  // ------- browser_fill -----------------------------------------------------

  const browser_fill = tool({
    description: `Fill a form field with a value.

Use this to:
- Enter credentials for authenticated reconnaissance
- Fill search boxes or input fields
- Enter test data into forms

IMPORTANT: For reliable form filling, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserFillInput,
    execute: async ({ element, ref, value }): Promise<BrowserFillResult> => {
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
        const refData = JSON.parse(require('node:fs').readFileSync(${JSON.stringify(SANDBOX_REFS_FILE)}, 'utf-8'));
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
    },
  });

  // ------- browser_evaluate -------------------------------------------------

  const browser_evaluate = tool({
    description: `Execute JavaScript in the browser context to extract information.

CRITICAL for SPA reconnaissance - use this to extract:
- React Router routes: window.__REACT_ROUTER_VERSION__
- Next.js data: window.__NEXT_DATA__ (reveals all page routes and API endpoints)
- Vue Router routes: window.__VUE_ROUTER__?.options?.routes
- API configuration: window.API_URL, window.API_BASE_URL, window.config
- Application state: window.__REDUX_STATE__, window.__INITIAL_STATE__
- All links on page: Array.from(document.querySelectorAll('a')).map(a => a.href)
- Service worker routes: navigator.serviceWorker?.controller

The JavaScript is executed in the page context and the result is returned.`,
    inputSchema: BrowserEvaluateInput,
    execute: async ({ script }): Promise<BrowserEvaluateResult> => {
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
    },
  });

  // ------- browser_console --------------------------------------------------

  const browser_console = tool({
    description: `Get console messages from the browser.

Use this to check for:
- Leaked API keys or secrets in console output
- Debug messages revealing internal URLs or endpoints
- Error messages exposing application structure
- Warnings about deprecated endpoints
- Network request failures revealing API patterns`,
    inputSchema: BrowserConsoleInput,
    execute: async (): Promise<BrowserConsoleResult> => {
      try {
        await setup();
        const result = (await runScript(
          `
    const fs = require('node:fs');
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
    },
  });

  // ------- browser_get_cookies ----------------------------------------------

  const browser_get_cookies = tool({
    description: `Extract cookies from the browser context, including httpOnly cookies.

CRITICAL: Use this after successful browser authentication to get session cookies that can be used in HTTP requests.

Returns all cookies including:
- Session cookies (often httpOnly, not accessible via document.cookie)
- Authentication tokens
- CSRF tokens

The returned cookies can be formatted as a Cookie header for use with http_request tool.`,
    inputSchema: BrowserGetCookiesInput,
    execute: async ({
      urls,
    }): Promise<{
      success: boolean;
      cookies?: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        httpOnly: boolean;
        secure: boolean;
      }>;
      cookieHeader?: string;
      error?: string;
    }> => {
      try {
        await setup();
        const result = (await runScript(
          `
    const urls = ${JSON.stringify(urls || [])};
    const cookies = urls.length > 0
      ? await context.cookies(urls)
      : await context.cookies();
    const cookieHeader = cookies.map(c => c.name + '=' + c.value).join('; ');
    resolve({ success: true, cookies, cookieHeader });
          `,
          15,
        )) as {
          success: boolean;
          cookies?: Array<{
            name: string;
            value: string;
            domain: string;
            path: string;
            httpOnly: boolean;
            secure: boolean;
          }>;
          cookieHeader?: string;
          error?: string;
        };

        return result;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return { success: false, error: message };
      }
    },
  });

  return {
    browser_navigate,
    browser_snapshot,
    browser_screenshot,
    browser_click,
    browser_fill,
    browser_evaluate,
    browser_console,
    browser_get_cookies,
  };
}
