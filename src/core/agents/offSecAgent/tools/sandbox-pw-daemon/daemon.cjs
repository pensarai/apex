#!/usr/bin/env node
/* eslint-disable */
/**
 * Apex Playwright Daemon — runs inside the Daytona sandbox.
 *
 * Owns ONE long-lived Chromium (launchPersistentContext) and ONE page for
 * the entire agent workflow. Exposes an HTTP API on 127.0.0.1:<ephemeral>
 * with one endpoint per existing browser tool. The host calls in via
 * `curl` from sandbox.execute; see sandboxPlaywrightClient.ts.
 *
 * Why: the per-tool-call relaunch model in sandboxPlaywright.ts wipes React
 * state, re-pays a ~7s Chromium cold start per call, and makes
 * domcontentloaded-timed snapshots unreliable on streaming-RSC pages.
 * This daemon eliminates all three failure modes. See the plan file at
 * ~/.claude/plans/feature-request-add-test-merry-flute.md for the full
 * rationale, protocol, and lifecycle contract.
 *
 * Contract notes:
 * - Tool response shapes MUST match what sandboxPlaywright.ts currently
 *   returns — agent prompts depend on these. Any field added or dropped
 *   here is a breaking change for the LLM.
 * - The cookie-seed file at /tmp/apex-cookie-seed.json is consumed ONCE
 *   at startup via context.addCookies (Node-side, so httpOnly cookies
 *   restore correctly — unlike document.cookie, which cannot set them).
 * - The refmap replaces /tmp/pw-refs.json with an in-memory Map that
 *   clears on main-frame navigation. Stale-ref errors are reported
 *   explicitly instead of silently misclicking.
 * - The console buffer replaces /tmp/pw-console-log.json with an
 *   in-memory ring of 200 entries, read-then-clear semantics identical
 *   to the existing tool.
 */

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

// --- constants ---------------------------------------------------------------

const COOKIE_SEED_PATH = "/tmp/apex-cookie-seed.json";
const PORT_FILE = "/tmp/apex-pw-port";
const LOG_FILE = "/tmp/apex-pw-daemon.log";
const PID_FILE = "/tmp/apex-pw-daemon.pid";
const EVIDENCE_DIR = "/tmp/evidence";
const USER_DATA_DIR = "/tmp/pw-user-data";
const CONSOLE_CAP = 200;
const LOG_CAP_BYTES = 100 * 1024;

const NAVIGATE_TIMEOUT_MS = 30_000;
const SCREENSHOT_TIMEOUT_MS = 20_000;
const ACTION_TIMEOUT_MS = 15_000;
const QUICK_TIMEOUT_MS = 5_000;
const HEALTHZ_TIMEOUT_MS = 2_000;
const NETWORKIDLE_BUDGET_MS = 1_500;

// --- tiny structured logger --------------------------------------------------

// Truncate an existing log to its last LOG_CAP_BYTES bytes at startup so
// long-running sandboxes don't accumulate unbounded daemon logs.
function initLog() {
  try {
    if (fs.existsSync(LOG_FILE)) {
      const stat = fs.statSync(LOG_FILE);
      if (stat.size > LOG_CAP_BYTES) {
        const buf = Buffer.alloc(LOG_CAP_BYTES);
        const fd = fs.openSync(LOG_FILE, "r");
        fs.readSync(fd, buf, 0, LOG_CAP_BYTES, stat.size - LOG_CAP_BYTES);
        fs.closeSync(fd);
        fs.writeFileSync(LOG_FILE, buf);
      }
    }
  } catch (_) {
    /* best-effort */
  }
}

function log(kind, obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), kind, ...obj });
  // fire-and-forget to stdout (captured by nohup) AND to a rotating file
  try {
    process.stdout.write(line + "\n");
  } catch (_) {
    /* stdout may be closed when the spawner exits */
  }
  try {
    fs.appendFileSync(LOG_FILE, line + "\n");
  } catch (_) {
    /* best-effort */
  }
}

// --- state -------------------------------------------------------------------

/** @type {import('playwright').BrowserContext | null} */
let context = null;
/** @type {import('playwright').Page | null} */
let page = null;
const refmap = new Map(); // ref (string) -> { role, name }
const consoleBuf = []; // [{ type, text, ts }]
let server = null;
let shuttingDown = false;
let chromiumPath = null;
let playwrightVersion = "unknown";
const startedAt = Date.now();

// --- request mutex -----------------------------------------------------------
//
// Playwright actions MUST be serialized on a single page, so we queue
// incoming HTTP requests behind a single Promise chain. Agent tool calls
// are already serialized at the Vercel AI SDK layer, but another client
// (health probe, chaos test) could interleave — the mutex guarantees
// correctness regardless of client behaviour.

let mutexTail = Promise.resolve();
function withMutex(fn) {
  const next = mutexTail
    .then(() => fn())
    .catch((e) => {
      throw e;
    });
  // Swallow the error on the chain so one failed action doesn't wedge
  // every subsequent one; callers still see their own error via `next`.
  mutexTail = next.catch(() => {});
  return next;
}

// --- helpers -----------------------------------------------------------------

function detectChromium() {
  for (const p of ["/usr/bin/chromium-browser", "/usr/bin/chromium"]) {
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch (_) {
      /* next */
    }
  }
  return undefined;
}

function ensureEvidenceDir() {
  try {
    fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  } catch (_) {
    /* best-effort */
  }
}

// Promise.race with a timeout that returns a structured error instead of
// throwing, so handlers can distinguish "action failed" from "daemon crashed".
function withTimeout(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${what} timed out after ${ms}ms`)),
      ms,
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Page crash detection: these error messages indicate the renderer died.
// We recreate the page on the same context (cookies + storage preserved)
// and re-install listeners, returning a structured error to the caller.
function isPageCrashError(err) {
  const msg = String((err && err.message) || err);
  return /Target closed|Page crashed|has been closed|Session closed/i.test(msg);
}

async function recreatePage() {
  try {
    if (page && !page.isClosed()) {
      await page.close().catch(() => {});
    }
  } catch (_) {
    /* best-effort */
  }
  page = await context.newPage();
  attachPageListeners(page);
  refmap.clear();
  log("page-recreated", { reason: "crash-recovery" });
}

function pushConsole(msg) {
  try {
    consoleBuf.push({
      type: msg.type(),
      text: msg.text(),
      ts: new Date().toISOString(),
    });
    if (consoleBuf.length > CONSOLE_CAP) {
      consoleBuf.splice(0, consoleBuf.length - CONSOLE_CAP);
    }
  } catch (_) {
    /* best-effort */
  }
}

function attachPageListeners(p) {
  p.on("console", pushConsole);
  p.on("framenavigated", (frame) => {
    try {
      // Refs are tied to the DOM of a specific rendered page. Navigation
      // away invalidates every previously-issued ref — clear the map and
      // force the caller to call /v1/snapshot again.
      if (frame === p.mainFrame()) {
        refmap.clear();
      }
    } catch (_) {
      /* best-effort */
    }
  });
}

// TAG_TO_ROLE — lifted from sandboxPlaywright.ts:694-702 verbatim so the
// click/fill fallback chain behaves identically to the per-call model.
const TAG_TO_ROLE = {
  a: "link",
  input: "textbox",
  select: "combobox",
  textarea: "textbox",
  img: "img",
  h1: "heading",
  h2: "heading",
  h3: "heading",
  h4: "heading",
  h5: "heading",
  h6: "heading",
  nav: "navigation",
  main: "main",
  header: "banner",
  footer: "contentinfo",
  aside: "complementary",
  article: "article",
  ul: "list",
  ol: "list",
  li: "listitem",
  dialog: "dialog",
  progress: "progressbar",
  option: "option",
  fieldset: "group",
  output: "status",
  button: "button",
  form: "form",
  table: "table",
};

// --- startup ----------------------------------------------------------------

async function startup() {
  initLog();
  ensureEvidenceDir();

  // 1. Capture PID for operator tooling + respawn detection.
  try {
    fs.writeFileSync(PID_FILE, String(process.pid));
  } catch (_) {
    /* best-effort */
  }

  // 2. Resolve Playwright + Chromium.
  let playwright;
  try {
    playwright = require("playwright");
  } catch (err) {
    log("fatal", { step: "require-playwright", error: String(err) });
    process.exit(2);
  }
  try {
    playwrightVersion = require("playwright/package.json").version;
  } catch (_) {
    playwrightVersion = "unknown";
  }
  chromiumPath = process.env.APEX_BROWSER_EXECUTABLE_PATH || detectChromium();

  // 3. Load + consume the cookie-seed file (one-shot). The host writes
  //    this BEFORE the main agent starts. See workflows/testCase.ts.
  let seedCookies = null;
  try {
    if (fs.existsSync(COOKIE_SEED_PATH)) {
      const raw = fs.readFileSync(COOKIE_SEED_PATH, "utf-8");
      seedCookies = JSON.parse(raw);
      if (!Array.isArray(seedCookies)) seedCookies = null;
    }
  } catch (err) {
    log("warn", { step: "read-cookie-seed", error: String(err) });
    seedCookies = null;
  }

  // 4. Launch Chromium — persistent context so the user-data dir carries
  //    cookies, localStorage, sessionStorage, service workers.
  try {
    context = await playwright.chromium.launchPersistentContext(USER_DATA_DIR, {
      headless: true,
      ...(chromiumPath ? { executablePath: chromiumPath } : {}),
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
      ],
    });
  } catch (err) {
    log("fatal", { step: "launch-chromium", error: String(err) });
    process.exit(3);
  }

  // 5. Apply cookie seed. Unlink on success — one-shot.
  if (seedCookies && seedCookies.length > 0) {
    try {
      await context.addCookies(seedCookies);
      log("info", { step: "cookies-seeded", count: seedCookies.length });
      try {
        fs.unlinkSync(COOKIE_SEED_PATH);
      } catch (_) {
        /* best-effort */
      }
    } catch (err) {
      log("warn", { step: "cookies-seed-failed", error: String(err) });
    }
  }

  // 6. Establish the persistent page.
  const pages = context.pages();
  page = pages.length > 0 ? pages[pages.length - 1] : await context.newPage();
  attachPageListeners(page);

  // 7. Bind HTTP server on an ephemeral port and publish atomically.
  server = http.createServer(router);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const { port } = server.address();
  try {
    fs.writeFileSync(PORT_FILE + ".tmp", String(port));
    fs.renameSync(PORT_FILE + ".tmp", PORT_FILE);
  } catch (err) {
    log("fatal", { step: "write-port-file", error: String(err) });
    process.exit(4);
  }

  log("ready", {
    port,
    pid: process.pid,
    playwrightVersion,
    chromiumPath: chromiumPath || "bundled",
  });

  installSignalHandlers();
}

function installSignalHandlers() {
  const shutdown = (signal) => async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    log("shutting-down", { signal });
    const deadline = Date.now() + 5_000;
    try {
      server && server.close();
    } catch (_) {
      /* ignore */
    }
    try {
      if (context) {
        await Promise.race([
          context.close(),
          new Promise((r) => setTimeout(r, Math.max(0, deadline - Date.now()))),
        ]);
      }
    } catch (_) {
      /* ignore */
    }
    try {
      fs.unlinkSync(PORT_FILE);
    } catch (_) {
      /* best-effort */
    }
    process.exit(0);
  };
  process.on("SIGTERM", shutdown("SIGTERM"));
  process.on("SIGINT", shutdown("SIGINT"));
}

// --- HTTP router -------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf-8");
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error("invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function writeJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function router(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;

  // Health + shutdown bypass the mutex — they need to respond even if a
  // Playwright action is in flight.
  if (req.method === "GET" && pathname === "/v1/healthz") {
    return writeJson(res, 200, {
      ok: true,
      uptimeMs: Date.now() - startedAt,
      pageUrl: (() => {
        try {
          return page ? page.url() : null;
        } catch (_) {
          return null;
        }
      })(),
      pid: process.pid,
      playwrightVersion,
      chromiumPath: chromiumPath || "bundled",
    });
  }

  if (req.method === "POST" && pathname === "/v1/shutdown") {
    writeJson(res, 200, { ok: true });
    // Schedule async to let the response flush.
    setImmediate(() => {
      process.kill(process.pid, "SIGTERM");
    });
    return;
  }

  if (req.method !== "POST" || !pathname.startsWith("/v1/")) {
    return writeJson(res, 404, {
      error: `unknown endpoint ${req.method} ${pathname}`,
    });
  }

  const action = pathname.slice("/v1/".length);
  const handler = HANDLERS[action];
  if (!handler) {
    return writeJson(res, 404, { error: `unknown action ${action}` });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return writeJson(res, 400, { error: String(err.message || err) });
  }

  try {
    const result = await withMutex(() => handler(body || {}));
    // handlers always return a {success, ...} or throw. Never 5xx on a
    // success:false body — that's reserved for daemon-liveness failures.
    return writeJson(res, 200, result);
  } catch (err) {
    log("handler-error", { action, error: String(err && err.message) });
    return writeJson(res, 500, {
      error: String(err && err.message) || "unknown handler error",
    });
  }
}

// --- handlers ----------------------------------------------------------------
//
// Each handler returns the EXACT tool-return shape from sandboxPlaywright.ts
// so the host-side wrapper is a pass-through. Do not add / rename fields
// here — agent prompts encode these.

const HANDLERS = {
  // --- navigate ---
  async navigate(args) {
    const { url } = args;
    if (typeof url !== "string" || url.length === 0) {
      return { success: false, url: "", error: "url is required" };
    }
    try {
      const result = await withTimeout(
        (async () => {
          await page.goto(url, {
            waitUntil: "domcontentloaded",
            timeout: NAVIGATE_TIMEOUT_MS,
          });
          // Give SPAs a brief window to hydrate AFTER domcontentloaded. If
          // networkidle never settles (long-polling, websockets), proceed.
          // This cost is paid ONCE per navigation, not per tool call.
          await page
            .waitForLoadState("networkidle", { timeout: NETWORKIDLE_BUDGET_MS })
            .catch(() => {});
          return { finalUrl: page.url(), title: await page.title() };
        })(),
        NAVIGATE_TIMEOUT_MS + NETWORKIDLE_BUDGET_MS + 2_000,
        "navigate",
      );
      return { success: true, url: result.finalUrl, title: result.title };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, url, error: String(err.message || err) };
    }
  },

  // --- snapshot ---
  async snapshot() {
    try {
      const treeData = await withTimeout(
        page.evaluate(() => {
          function tagToAriaRole(el) {
            const tag = el.tagName.toLowerCase();
            switch (tag) {
              case "a":
                return el.hasAttribute("href") ? "link" : "generic";
              case "button":
                return "button";
              case "input": {
                const t = (el.getAttribute("type") || "text").toLowerCase();
                if (
                  t === "button" ||
                  t === "submit" ||
                  t === "reset" ||
                  t === "image"
                )
                  return "button";
                if (t === "checkbox") return "checkbox";
                if (t === "radio") return "radio";
                if (t === "range") return "slider";
                if (t === "number") return "spinbutton";
                if (t === "search") return "searchbox";
                return "textbox";
              }
              case "select":
                return el.hasAttribute("multiple") ? "listbox" : "combobox";
              case "textarea":
                return "textbox";
              case "img":
                return "img";
              case "h1":
              case "h2":
              case "h3":
              case "h4":
              case "h5":
              case "h6":
                return "heading";
              case "table":
                return "table";
              case "form":
                return "form";
              case "nav":
                return "navigation";
              case "main":
                return "main";
              case "header":
                return "banner";
              case "footer":
                return "contentinfo";
              case "aside":
                return "complementary";
              case "article":
                return "article";
              case "ul":
              case "ol":
                return "list";
              case "li":
                return "listitem";
              case "dialog":
                return "dialog";
              case "progress":
                return "progressbar";
              case "option":
                return "option";
              case "fieldset":
                return "group";
              case "output":
                return "status";
              default:
                return tag;
            }
          }
          function walk(el, depth) {
            const role = el.getAttribute("role") || tagToAriaRole(el);
            const name =
              el.getAttribute("aria-label") ||
              el.getAttribute("name") ||
              el.getAttribute("placeholder") ||
              (el.tagName === "INPUT" || el.tagName === "TEXTAREA"
                ? el.getAttribute("type") || ""
                : "") ||
              (el.textContent ? el.textContent.trim().substring(0, 60) : "");
            const value =
              el.value !== undefined && el.value !== "" ? el.value : undefined;
            const children = [];
            for (const child of el.children) {
              children.push(walk(child, depth + 1));
            }
            return { role, name, value, children, depth };
          }
          return walk(document.body, 0);
        }),
        ACTION_TIMEOUT_MS,
        "snapshot",
      );

      refmap.clear();
      let refId = 0;
      const lines = [];
      function formatNode(node, depth) {
        if (!node) return;
        const ref = "e" + refId++;
        const indent = "  ".repeat(depth);
        let desc = indent + "[ref=" + ref + "] " + (node.role || "unknown");
        if (node.name) desc += ' "' + String(node.name).substring(0, 80) + '"';
        if (node.value)
          desc += ' value="' + String(node.value).substring(0, 40) + '"';
        lines.push(desc);
        refmap.set(ref, { role: node.role, name: node.name || "" });
        if (node.children) {
          for (const child of node.children) formatNode(child, depth + 1);
        }
      }
      formatNode(treeData, 0);
      return { success: true, snapshot: lines.join("\n") };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, error: String(err.message || err) };
    }
  },

  // --- screenshot ---
  async screenshot(args) {
    const { filename, fullPage } = args;
    if (typeof filename !== "string" || filename.length === 0) {
      return { success: false, error: "filename is required" };
    }
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const name = `${filename}_${ts}.png`;
      const sandboxPath = path.join(EVIDENCE_DIR, name);
      ensureEvidenceDir();
      const buf = await withTimeout(
        page.screenshot({ fullPage: fullPage === true }),
        SCREENSHOT_TIMEOUT_MS,
        "screenshot",
      );
      fs.writeFileSync(sandboxPath, buf);
      return {
        success: true,
        sandboxPath,
        bytesB64: buf.toString("base64"),
      };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, error: String(err.message || err) };
    }
  },

  // --- click ---
  async click(args) {
    const { element, ref } = args;
    if (typeof element !== "string") {
      return { success: false, element: "", error: "element is required" };
    }
    try {
      // Ref-first path: resolve via in-memory refmap. If the map is empty
      // (post-navigation) or the ref is unknown, surface a structured
      // error so the agent knows to call /v1/snapshot again.
      if (ref) {
        const info = refmap.get(ref);
        if (!info || !info.role) {
          return {
            success: false,
            element,
            error:
              "ref stale — call browser_snapshot first (the page has navigated since the last snapshot)",
          };
        }
        const role = TAG_TO_ROLE[info.role] || info.role;
        await withTimeout(
          page
            .getByRole(role, { name: info.name })
            .first()
            .click({ timeout: ACTION_TIMEOUT_MS - 2_000 }),
          ACTION_TIMEOUT_MS,
          "click-by-ref",
        );
        return { success: true, element, result: "Clicked via ref " + ref };
      }

      // Fallback chain — matches sandboxPlaywright.ts:716-738 verbatim.
      try {
        await page
          .getByRole("button", { name: element })
          .first()
          .click({ timeout: QUICK_TIMEOUT_MS });
        return {
          success: true,
          element,
          result: "Clicked button matching: " + element,
        };
      } catch (_) {
        /* next */
      }
      try {
        await page
          .getByRole("link", { name: element })
          .first()
          .click({ timeout: QUICK_TIMEOUT_MS });
        return {
          success: true,
          element,
          result: "Clicked link matching: " + element,
        };
      } catch (_) {
        /* next */
      }
      try {
        await page
          .getByText(element)
          .first()
          .click({ timeout: QUICK_TIMEOUT_MS });
        return {
          success: true,
          element,
          result: "Clicked text matching: " + element,
        };
      } catch (_) {
        /* next */
      }
      await page
        .locator("text=" + element)
        .first()
        .click({ timeout: ACTION_TIMEOUT_MS - 5_000 });
      return {
        success: true,
        element,
        result: "Clicked via text locator: " + element,
      };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, element, error: String(err.message || err) };
    }
  },

  // --- fill ---
  async fill(args) {
    const { element, ref, value } = args;
    if (typeof element !== "string" || typeof value !== "string") {
      return {
        success: false,
        element: element || "",
        error: "element and value are required",
      };
    }
    try {
      if (ref) {
        const info = refmap.get(ref);
        if (!info || !info.role) {
          return {
            success: false,
            element,
            error:
              "ref stale — call browser_snapshot first (the page has navigated since the last snapshot)",
          };
        }
        const role = TAG_TO_ROLE[info.role] || info.role;
        await withTimeout(
          page
            .getByRole(role, { name: info.name })
            .first()
            .fill(value, { timeout: ACTION_TIMEOUT_MS - 2_000 }),
          ACTION_TIMEOUT_MS,
          "fill-by-ref",
        );
        return { success: true, element, result: "Filled via ref " + ref };
      }

      // Fallback chain — matches sandboxPlaywright.ts:796-817 verbatim.
      try {
        await page
          .getByLabel(element)
          .first()
          .fill(value, { timeout: QUICK_TIMEOUT_MS });
        return {
          success: true,
          element,
          result: "Filled by label: " + element,
        };
      } catch (_) {
        /* next */
      }
      try {
        await page
          .getByPlaceholder(element)
          .first()
          .fill(value, { timeout: QUICK_TIMEOUT_MS });
        return {
          success: true,
          element,
          result: "Filled by placeholder: " + element,
        };
      } catch (_) {
        /* next */
      }
      try {
        await page
          .getByRole("textbox", { name: element })
          .first()
          .fill(value, { timeout: QUICK_TIMEOUT_MS });
        return {
          success: true,
          element,
          result: "Filled textbox matching: " + element,
        };
      } catch (_) {
        /* next */
      }
      await page
        .locator('[placeholder*="' + element.replace(/"/g, "") + '" i]')
        .first()
        .fill(value, { timeout: ACTION_TIMEOUT_MS - 5_000 });
      return {
        success: true,
        element,
        result: "Filled via placeholder locator: " + element,
      };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, element, error: String(err.message || err) };
    }
  },

  // --- press_key ---
  // Playwright's page.keyboard.press fires a TRUSTED keyboard event —
  // unlike `element.dispatchEvent(new KeyboardEvent(...))`, which is
  // marked isTrusted: false and rejected by modern form handlers. This
  // is the correct way to trigger submit-on-Enter or keyboard shortcuts.
  // Accepts any Playwright-supported key string: "Enter", "Escape",
  // "Tab", "ArrowDown", "Control+A", etc.
  async press_key(args) {
    const { key } = args;
    if (typeof key !== "string" || key.length === 0) {
      return { success: false, error: "key is required" };
    }
    try {
      await withTimeout(
        page.keyboard.press(key),
        ACTION_TIMEOUT_MS,
        "press_key",
      );
      return { success: true, key };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, key, error: String(err.message || err) };
    }
  },

  // --- evaluate ---
  async evaluate(args) {
    const { script } = args;
    if (typeof script !== "string") {
      return { success: false, script: "", error: "script is required" };
    }
    try {
      // Match the per-call model's heuristic: if the script LOOKS like a
      // function expression, pass it through; otherwise wrap it as a
      // thunk. See sandboxPlaywright.ts:849-853.
      const isFunction =
        /^\s*(async\s+)?\(/.test(script) ||
        /^\s*(async\s+)?function\s*\(/.test(script);
      const fnScript = isFunction ? script : `() => (${script})`;
      const fn = new Function("return (" + fnScript + ")")();
      const result = await withTimeout(
        page.evaluate(fn),
        ACTION_TIMEOUT_MS,
        "evaluate",
      );
      return { success: true, script, result };
    } catch (err) {
      if (isPageCrashError(err)) {
        await recreatePage().catch(() => {});
      }
      return { success: false, script, error: String(err.message || err) };
    }
  },

  // --- console ---
  async console() {
    // Read-clear semantics — match sandboxPlaywright.ts:893-897.
    const copy = consoleBuf.splice(0, consoleBuf.length);
    return { success: true, messages: copy, result: copy };
  },

  // --- cookies ---
  async cookies(args) {
    const { urls } = args;
    try {
      const list = await withTimeout(
        Array.isArray(urls) && urls.length > 0
          ? context.cookies(urls)
          : context.cookies(),
        QUICK_TIMEOUT_MS,
        "cookies",
      );
      const cookieHeader = list.map((c) => c.name + "=" + c.value).join("; ");
      return { success: true, cookies: list, cookieHeader };
    } catch (err) {
      return { success: false, error: String(err.message || err) };
    }
  },

  // --- reload-cookies (belt-and-suspenders, see plan R4) ---
  async ["reload-cookies"]() {
    try {
      if (!fs.existsSync(COOKIE_SEED_PATH)) {
        return { success: true, applied: 0, note: "no seed file present" };
      }
      const parsed = JSON.parse(fs.readFileSync(COOKIE_SEED_PATH, "utf-8"));
      if (!Array.isArray(parsed)) {
        return { success: false, error: "seed file is not a JSON array" };
      }
      if (parsed.length > 0) {
        await context.addCookies(parsed);
      }
      try {
        fs.unlinkSync(COOKIE_SEED_PATH);
      } catch (_) {
        /* best-effort */
      }
      return { success: true, applied: parsed.length };
    } catch (err) {
      return { success: false, error: String(err.message || err) };
    }
  },
};

// --- main --------------------------------------------------------------------

startup().catch((err) => {
  log("fatal", { step: "startup", error: String(err.message || err) });
  process.exit(5);
});
