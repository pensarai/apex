/**
 * Live integration test for sandbox Playwright browser tools.
 *
 * Uses the Daytona REST API directly (not the SDK) to create a sandbox,
 * wraps it as a UnifiedSandbox, then exercises the full sandbox Playwright
 * lifecycle:
 *   1. Check / install Playwright
 *   2. Launch Chromium via CDP
 *   3. Run browser tools (navigate, snapshot, click, evaluate, cookies, screenshot)
 *
 * Usage:
 *   DAYTONA_API_KEY=<key> bun run scripts/test-sandbox-playwright.ts
 */

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  checkSandboxPlaywright,
  createSandboxBrowserTools,
  ensureSandboxBrowser,
  installSandboxPlaywright,
  type SandboxExecuteOptions,
  type SandboxExecutionResult,
  type ToolContext,
  type UnifiedSandbox,
} from "../src/core/agents/offSecAgent";
import { inProcessSubagentSpawner } from "../src/core/agents/offSecAgent/subagentSpawner";

// ---------------------------------------------------------------------------
// Daytona REST API helpers
// ---------------------------------------------------------------------------

const API_BASE = "https://app.daytona.io/api";
const API_KEY = process.env.DAYTONA_API_KEY ?? "";

const headers = {
  Authorization: `Bearer ${API_KEY}`,
  "Content-Type": "application/json",
};

interface DaytonaSandboxInfo {
  id: string;
  state: string;
  toolboxProxyUrl?: string;
}

async function createDaytonaSandbox(): Promise<DaytonaSandboxInfo> {
  const res = await fetch(`${API_BASE}/sandbox`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      image: "daytona/node:20-slim",
      resources: { cpu: 2, memory: 4, disk: 10 },
      public: true,
      autoStopInterval: 0,
    }),
  });
  if (!res.ok)
    throw new Error(`Create sandbox failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as DaytonaSandboxInfo;
}

async function waitForSandboxReady(
  id: string,
  timeoutMs = 60000,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await fetch(`${API_BASE}/sandbox/${id}`, { headers });
    if (res.ok) {
      const info = (await res.json()) as DaytonaSandboxInfo;
      if (info.state === "started") return;
      if (info.state === "error") throw new Error(`Sandbox in error state`);
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Sandbox not ready within ${timeoutMs}ms`);
}

const TOOLBOX_PROXY = "https://proxy.app.daytona.io/toolbox";

async function execInSandbox(
  id: string,
  command: string,
  timeout?: number,
): Promise<{ exitCode: number; result: string }> {
  const res = await fetch(`${TOOLBOX_PROXY}/${id}/process/execute`, {
    method: "POST",
    headers,
    body: JSON.stringify({ command, timeout }),
    signal: timeout ? AbortSignal.timeout((timeout + 30) * 1000) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Exec failed: ${res.status} ${text}`);
  }
  return (await res.json()) as { exitCode: number; result: string };
}

async function deleteSandbox(id: string): Promise<void> {
  await fetch(`${API_BASE}/sandbox/${id}`, { method: "DELETE", headers });
}

// ---------------------------------------------------------------------------
// UnifiedSandbox wrapper
// ---------------------------------------------------------------------------

function makeSandbox(id: string): UnifiedSandbox {
  return {
    type: "linux",
    async execute(
      command: string,
      opts?: SandboxExecuteOptions,
    ): Promise<SandboxExecutionResult> {
      try {
        // Daytona toolbox API doesn't run commands in a shell by default.
        // Base64-encode the entire command and pipe through bash to avoid
        // all quoting / escaping issues with nested quotes. We need bash
        // to handle the pipes, so wrap in bash -c (base64 is pipe-safe).
        const b64 = Buffer.from(command).toString("base64");
        const wrapped = `bash -c "echo ${b64} | base64 -d | bash"`;
        const result = await execInSandbox(id, wrapped, opts?.timeout);
        return {
          stdout: result.result ?? "",
          stderr: "",
          exitCode: result.exitCode ?? 0,
          success: result.exitCode === 0,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { stdout: "", stderr: msg, exitCode: 1, success: false };
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

let passCount = 0;
let failCount = 0;

function log(label: string, msg: string) {
  console.log(`[${label}] ${msg}`);
}

function pass(name: string) {
  passCount++;
  console.log(`  ✅ ${name}`);
}

function fail(name: string, err: unknown) {
  failCount++;
  console.error(
    `  ❌ ${name}: ${err instanceof Error ? err.message : String(err)}`,
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  if (!API_KEY) {
    console.error("DAYTONA_API_KEY is required");
    process.exit(1);
  }

  let sandboxId: string | undefined;

  try {
    // ---- Create sandbox ----------------------------------------------------
    log("setup", "Creating Daytona sandbox...");
    const info = await createDaytonaSandbox();
    sandboxId = info.id;
    log("setup", `Sandbox created: ${sandboxId} (state: ${info.state})`);

    if (info.state !== "started") {
      log("setup", "Waiting for sandbox to start...");
      await waitForSandboxReady(sandboxId);
    }
    pass("Sandbox is ready");

    const sandbox = makeSandbox(sandboxId);

    // Verify base environment
    const nodeCheck = await sandbox.execute("node --version");
    log("setup", `Node.js: ${nodeCheck.stdout.trim()}`);
    pass(`Node.js available: ${nodeCheck.stdout.trim()}`);

    // ---- Step 1: Check Playwright (should be false) ------------------------
    log("test", "Step 1: checkSandboxPlaywright (expect false)");
    const before = await checkSandboxPlaywright(sandbox);
    if (!before) {
      pass("Playwright not yet installed (expected)");
    } else {
      fail("check should be false before install", "got true");
    }

    // ---- Step 2: Install Playwright ----------------------------------------
    log("test", "Step 2: installSandboxPlaywright (may take 1-3 min)...");
    const t0 = Date.now();
    await installSandboxPlaywright(sandbox);
    pass(`Playwright installed in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

    // ---- Step 3: Check again (should be true) ------------------------------
    log("test", "Step 3: checkSandboxPlaywright (expect true)");

    // Debug: check what's in the sandbox
    const debugLs = await sandbox.execute(
      "ls /tmp/sandbox-playwright/node_modules/ 2>&1",
    );
    log("debug", `node_modules: ${debugLs.stdout.trim()}`);
    const debugCheck = await sandbox.execute(
      "cd /tmp/sandbox-playwright && echo 'console.log(\"PW_OK\")' > /tmp/dbg.js && node /tmp/dbg.js 2>&1",
    );
    log(
      "debug",
      `simple script: ${debugCheck.stdout.trim()} (exit: ${debugCheck.exitCode})`,
    );
    const debugReq = await sandbox.execute(
      'cd /tmp/sandbox-playwright && echo \'try{require("playwright");console.log("PW_OK")}catch(e){console.log("FAIL:"+e.message)}\' > /tmp/dbg2.js && node /tmp/dbg2.js 2>&1',
    );
    log(
      "debug",
      `require test: ${debugReq.stdout.trim()} (exit: ${debugReq.exitCode})`,
    );

    const after = await checkSandboxPlaywright(sandbox);
    if (after) {
      pass("Playwright verified installed");
    } else {
      fail("check should be true after install", "got false");
    }

    // ---- Step 4: Launch browser --------------------------------------------
    log("test", "Step 4: ensureSandboxBrowser (launch Chromium)...");
    const t1 = Date.now();
    await ensureSandboxBrowser(sandbox);
    pass(`Chromium launched in ${((Date.now() - t1) / 1000).toFixed(1)}s`);

    // Verify CDP
    const cdpCheck = await sandbox.execute(
      "curl -sf http://127.0.0.1:9222/json/version",
    );
    if (cdpCheck.success) {
      pass("Chromium CDP endpoint responding");
    } else {
      fail("CDP check", cdpCheck.stderr);
    }

    // ---- Step 5: Test browser tools ----------------------------------------
    log("test", "Step 5: Testing browser tools end-to-end");

    const testDir = join(process.cwd(), ".pensar", "test-sandbox-pw");
    mkdirSync(join(testDir, "evidence"), { recursive: true });
    mkdirSync(join(testDir, "logs"), { recursive: true });
    mkdirSync(join(testDir, "pocs"), { recursive: true });
    mkdirSync(join(testDir, "findings"), { recursive: true });
    mkdirSync(join(testDir, "scratchpad"), { recursive: true });

    const ctx: ToolContext = {
      subagentSpawner: inProcessSubagentSpawner,
      session: {
        id: "test-sandbox-pw",
        version: "0.0.1",
        targets: ["example.com"],
        name: "Test Sandbox PW",
        time: { created: Date.now(), updated: Date.now() },
        config: {
          mode: "auto" as const,
          outcomeGuidance: "test",
        },
        rootPath: testDir,
        logsPath: join(testDir, "logs"),
        pocsPath: join(testDir, "pocs"),
        scratchpadPath: join(testDir, "scratchpad"),
        findingsPath: join(testDir, "findings"),
      } as ToolContext["session"],
      agentCwd: testDir,
      target: "https://example.com",
      sandbox,
    };

    const tools = createSandboxBrowserTools(ctx);
    const callOpts = {
      toolCallId: "t",
      messages: [] as never[],
      abortSignal: undefined as never,
    };

    // 5a: browser_navigate
    log("tool", "browser_navigate → https://example.com");
    const browserNavigate = tools.browser_navigate.execute;
    if (!browserNavigate) throw new Error("browser_navigate missing execute");
    const nav = (await browserNavigate(
      { url: "https://example.com", toolCallDescription: "test" },
      callOpts,
    )) as { success: boolean; url?: string; title?: string; error?: string };
    if (nav.success) {
      pass(`navigate: url=${nav.url}, title="${nav.title}"`);
    } else {
      fail("navigate", nav.error);
    }

    // 5b: browser_evaluate
    log("tool", "browser_evaluate → document.title");
    const browserEvaluate = tools.browser_evaluate.execute;
    if (!browserEvaluate) throw new Error("browser_evaluate missing execute");
    const evalR = (await browserEvaluate(
      { script: "document.title", toolCallDescription: "test" },
      callOpts,
    )) as { success: boolean; result?: unknown; error?: string };
    if (evalR.success) {
      pass(`evaluate: title = "${evalR.result}"`);
    } else {
      fail("evaluate", evalR.error);
    }

    // 5c: browser_snapshot
    log("tool", "browser_snapshot");
    const browserSnapshot = tools.browser_snapshot.execute;
    if (!browserSnapshot) throw new Error("browser_snapshot missing execute");
    const snap = (await browserSnapshot(
      { toolCallDescription: "test" },
      callOpts,
    )) as { success: boolean; snapshot?: string; error?: string };
    if (snap.success && snap.snapshot) {
      console.log(
        `  snapshot (first 400 chars):\n${snap.snapshot.substring(0, 400)}`,
      );
      pass(`snapshot: ${snap.snapshot.length} chars`);
    } else {
      fail("snapshot", snap.error);
    }

    // 5d: browser_get_cookies
    log("tool", "browser_get_cookies");
    const browserGetCookies = tools.browser_get_cookies.execute;
    if (!browserGetCookies)
      throw new Error("browser_get_cookies missing execute");
    const cookies = (await browserGetCookies(
      { toolCallDescription: "test" },
      callOpts,
    )) as { success: boolean; cookies?: unknown[]; error?: string };
    if (cookies.success) {
      pass(`cookies: ${cookies.cookies?.length ?? 0} cookie(s)`);
    } else {
      fail("cookies", cookies.error);
    }

    // 5e: browser_screenshot
    log("tool", "browser_screenshot");
    const browserScreenshot = tools.browser_screenshot.execute;
    if (!browserScreenshot)
      throw new Error("browser_screenshot missing execute");
    const ss = (await browserScreenshot(
      { filename: "test_example_com", toolCallDescription: "test" },
      callOpts,
    )) as { success: boolean; path?: string; error?: string };
    if (ss.success) {
      pass(`screenshot: ${ss.path}`);
    } else {
      fail("screenshot", ss.error);
    }

    // 5f: browser_console
    log("tool", "browser_console");
    const browserConsole = tools.browser_console.execute;
    if (!browserConsole) throw new Error("browser_console missing execute");
    const cons = (await browserConsole(
      { toolCallDescription: "test" },
      callOpts,
    )) as { success: boolean; messages?: unknown[]; error?: string };
    if (cons.success) {
      pass(`console: ${cons.messages?.length ?? 0} message(s)`);
    } else {
      fail("console", cons.error);
    }

    // ---- Summary -----------------------------------------------------------
    console.log(`\n${"=".repeat(60)}`);
    console.log(`Results: ${passCount} passed, ${failCount} failed`);
    if (failCount === 0) {
      console.log("🎉 All tests passed!");
    } else {
      console.log("⚠️  Some tests failed.");
    }
    console.log("=".repeat(60));
  } catch (error) {
    console.error(
      "\n❌ Fatal error:",
      error instanceof Error ? error.message : String(error),
    );
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }
    process.exitCode = 1;
  } finally {
    if (sandboxId) {
      log("cleanup", "Deleting sandbox...");
      try {
        await deleteSandbox(sandboxId);
        log("cleanup", "Sandbox deleted.");
      } catch (err) {
        console.error(
          "Cleanup failed:",
          err instanceof Error ? err.message : String(err),
        );
      }
    }
  }
}

main();
