/**
 * Phase 3 integration test — validates the host client ↔ daemon loop
 * inside a real Daytona sandbox.
 *
 * Pre-requisites provisioned in beforeAll:
 *   - node:20-slim sandbox (fast boot, ~600ms on cached snapshot)
 *   - curl, procps, iproute2 installed via apt
 *   - Playwright + Chromium installed at /opt/sandbox-playwright
 *     (matches what @console/sandbox's buildSandboxImage does at
 *     production image-build time; see createSandbox.ts:558-563)
 *
 * Gated on DAYTONA_API_KEY. Runs full suite (~3-4 min cold, ~30s warm).
 */

import { Daytona, type Sandbox as DaytonaSandbox } from "@daytonaio/sdk";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { config } from "dotenv";
import type {
  SandboxExecuteOptions,
  SandboxExecutionResult,
  UnifiedSandbox,
} from "./sandbox";
import {
  ensureDaemon,
  callDaemon,
  shutdownDaemon,
} from "./sandboxPlaywrightClient";

config();

const SETUP_TIMEOUT_MS = 600_000;
const TEST_TIMEOUT_MS = 120_000;

// Adapter so the Daytona SDK sandbox satisfies the UnifiedSandbox
// interface the client expects. The concrete `LinuxSandbox` at
// packages/sandbox/createSandbox.ts does the same translation with more
// bells and whistles (retry, structured stderr). For tests we keep it
// minimal.
function toUnified(sbx: DaytonaSandbox): UnifiedSandbox {
  return {
    type: "linux",
    async execute(
      command: string,
      opts?: SandboxExecuteOptions,
    ): Promise<SandboxExecutionResult> {
      const r = await sbx.process.executeCommand(
        command,
        opts?.cwd,
        opts?.envVars,
        opts?.timeout,
      );
      return {
        stdout: r.result || "",
        stderr: "",
        exitCode: r.exitCode ?? 0,
        success: (r.exitCode ?? 0) === 0,
      };
    },
    // Use Daytona SDK's native uploadFile — faster than base64-over-exec.
    // This is the same pathway LinuxSandbox.uploadFile uses at
    // packages/sandbox/createSandbox.ts:166-173.
    async uploadFile(content: string | Buffer, remotePath: string) {
      // Write locally in a unique file then pass the path to the
      // Daytona SDK. The local filename is a bare basename (no leading
      // slash) so path.join with os.tmpdir() does the right thing.
      const fs = await import("fs/promises");
      const os = await import("os");
      const path = await import("path");
      const basename = `apex-upload-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const localPath = path.join(os.tmpdir(), basename);
      await fs.writeFile(
        localPath,
        typeof content === "string" ? Buffer.from(content, "utf-8") : content,
      );
      try {
        await sbx.fs.uploadFile(localPath, remotePath);
      } finally {
        await fs.unlink(localPath).catch(() => {});
      }
    },
  };
}

describe.skipIf(!process.env.DAYTONA_API_KEY)(
  "sandboxPlaywrightClient (Phase 3 integration)",
  () => {
    let daytona: Daytona;
    let rawSandbox: DaytonaSandbox;
    let sandbox: UnifiedSandbox;

    beforeAll(async () => {
      const apiKey = process.env.DAYTONA_API_KEY;
      if (!apiKey) throw new Error("DAYTONA_API_KEY is required");
      daytona = new Daytona({
        apiKey,
        apiUrl: process.env.DAYTONA_API_URL ?? "https://app.daytona.io/api",
      });

      console.log("[p3] creating sandbox...");
      const t0 = Date.now();
      rawSandbox = await daytona.create(
        {
          image: "node:20-slim",
          resources: { cpu: 2, memory: 2, disk: 5 },
          public: false,
          networkBlockAll: false,
        },
        { timeout: 300_000 },
      );
      console.log(`[p3] sandbox ready ${rawSandbox.id} (${Date.now() - t0}ms)`);
      await rawSandbox.setAutostopInterval(0).catch(() => {});

      // Install OS deps + Playwright. The daemon looks for Playwright at
      // /opt/sandbox-playwright/node_modules — mirror the production
      // install path so the daemon's require('playwright') resolves.
      console.log(
        "[p3] installing system deps + Playwright (may take 1-2 min cold)...",
      );
      const setup = await rawSandbox.process.executeCommand(
        // dash-compatible: `&&` short-circuits on failure. No bash-only
        // `set -euxo pipefail`. Swallow stdout (noisy npm/apt output)
        // but preserve exit code via the chain.
        "apt-get update -qq >/dev/null 2>&1 && " +
          "apt-get install -y -qq curl procps iproute2 >/dev/null 2>&1 && " +
          "mkdir -p /opt/sandbox-playwright && " +
          "cd /opt/sandbox-playwright && " +
          "npm init -y --silent >/dev/null && " +
          "npm install --silent playwright@1.49.0 >/dev/null 2>&1 && " +
          "npx --yes playwright install chromium --with-deps >/dev/null 2>&1 && " +
          "echo OK",
        undefined,
        undefined,
        300,
      );
      if ((setup.exitCode ?? 0) !== 0 || !(setup.result || "").includes("OK")) {
        throw new Error(
          `Playwright install failed: exitCode=${setup.exitCode}\n${setup.result}`,
        );
      }

      sandbox = toUnified(rawSandbox);
    }, SETUP_TIMEOUT_MS);

    afterAll(async () => {
      await Promise.allSettled([
        // Graceful shutdown so the daemon drains cleanly; sandbox delete
        // will kill anything left behind.
        sandbox ? shutdownDaemon(sandbox) : undefined,
        rawSandbox?.process.executeCommand(
          "pkill -f apex-pw-daemon 2>/dev/null; true",
        ),
        daytona?.delete(rawSandbox),
      ]);
    }, SETUP_TIMEOUT_MS);

    it(
      "ensureDaemon boots, returns a usable handle, and is memoized",
      async () => {
        const h1 = await ensureDaemon(sandbox);
        expect(h1.port).toBeGreaterThan(0);
        expect(h1.playwrightVersion).toMatch(/^\d/); // non-unknown
        expect(h1.respawnCount).toBe(0);
        // Second call: same handle (memoized, not a new spawn).
        const h2 = await ensureDaemon(sandbox);
        expect(h2).toBe(h1);
      },
      TEST_TIMEOUT_MS,
    );

    it(
      "navigate + snapshot + evaluate: tool contracts + SPA state persistence",
      async () => {
        const nav = await callDaemon<{
          success: boolean;
          url: string;
          title?: string;
          error?: string;
        }>(sandbox, "navigate", {
          url:
            "data:text/html," +
            encodeURIComponent(
              `<div>
                <button id="t1" onclick="document.getElementById('panel').innerText='TAB_ONE_SHOWN'">Tab1</button>
                <button id="t2" onclick="document.getElementById('panel').innerText='TAB_TWO_SHOWN'">Tab2</button>
                <div id="panel">initial</div>
              </div>`,
            ),
        });
        expect(nav.success, `navigate failed: ${nav.error}`).toBe(true);

        const snap = await callDaemon<{
          success: boolean;
          snapshot?: string;
          error?: string;
        }>(sandbox, "snapshot", {});
        expect(snap.success).toBe(true);
        expect(snap.snapshot).toContain("[ref=");
        expect(snap.snapshot).toContain("Tab2");

        // Click Tab2 via text (no ref) — exercises the fallback chain
        // AND mutates the page (sets panel innerText to TAB_TWO_SHOWN).
        const click = await callDaemon<{
          success: boolean;
          result?: string;
          error?: string;
        }>(sandbox, "click", { element: "Tab2" });
        expect(click.success, `click failed: ${click.error}`).toBe(true);

        // THE KEY TEST: the evaluate below runs in a SEPARATE HTTP
        // request. With the old per-call model the page would be a
        // fresh navigation at this point and panel.innerText would be
        // "initial". With the daemon, the page persists and we see the
        // post-click mutation.
        const ev = await callDaemon<{
          success: boolean;
          result?: unknown;
          error?: string;
        }>(sandbox, "evaluate", {
          script: "document.getElementById('panel').innerText",
        });
        expect(ev.success).toBe(true);
        expect(ev.result).toBe("TAB_TWO_SHOWN");
      },
      TEST_TIMEOUT_MS,
    );

    it(
      "console buffer + cookies round-trip cleanly",
      async () => {
        // Fire 250 console logs via evaluate, then drain buffer — expect
        // exactly 200 (ring-buffer cap) with last-wins semantics.
        const logResult = await callDaemon<{ success: boolean }>(
          sandbox,
          "evaluate",
          {
            script:
              "() => { for (let i = 0; i < 250; i++) console.log('m' + i); return true; }",
          },
        );
        expect(logResult.success).toBe(true);
        await new Promise((r) => setTimeout(r, 500)); // let console events flush

        const consoleOut = await callDaemon<{
          success: boolean;
          messages: Array<{ type: string; text: string }>;
        }>(sandbox, "console", {});
        expect(consoleOut.success).toBe(true);
        expect(consoleOut.messages.length).toBe(200);
        expect(consoleOut.messages[0].text).toBe("m50");
        expect(consoleOut.messages[199].text).toBe("m249");

        // Second drain should be empty (read-clear semantics).
        const consoleOut2 = await callDaemon<{
          messages: Array<unknown>;
        }>(sandbox, "console", {});
        expect(consoleOut2.messages.length).toBe(0);

        // Cookies should return an empty array for a data: URL page.
        const cookies = await callDaemon<{
          success: boolean;
          cookies: unknown[];
        }>(sandbox, "cookies", {});
        expect(cookies.success).toBe(true);
        expect(Array.isArray(cookies.cookies)).toBe(true);
      },
      TEST_TIMEOUT_MS,
    );

    it(
      "press_key fires a trusted keyboard event (Fix B)",
      async () => {
        // Navigate to a form whose onSubmit increments a counter exposed
        // on window. Press Enter from a focused input. If press_key fires
        // a TRUSTED event (Playwright's page.keyboard.press), the browser
        // treats the keypress as real and submits the form. If it were a
        // synthetic dispatchEvent (isTrusted:false), modern browsers
        // would ignore it for form submission and the counter stays at 0.
        //
        // The input uses autofocus so the <input> is the focused element
        // on page load — this avoids the daemon's evaluate-script
        // multi-statement trap and exercises only the press_key path.
        await callDaemon(sandbox, "navigate", {
          url:
            "data:text/html," +
            encodeURIComponent(
              `<script>window.submitCount = 0;</script>
              <form onsubmit="event.preventDefault(); window.submitCount++;">
                <input id="i" type="text" autofocus />
              </form>`,
            ),
        });
        const press = await callDaemon<{
          success: boolean;
          key?: string;
          error?: string;
        }>(sandbox, "press_key", { key: "Enter" });
        expect(press.success, `press_key failed: ${press.error}`).toBe(true);
        // Small pause so the submit handler increments the counter.
        await new Promise((r) => setTimeout(r, 200));
        const out = await callDaemon<{ success: boolean; result: unknown }>(
          sandbox,
          "evaluate",
          { script: "window.submitCount" },
        );
        // Must be >= 1 — trusted Enter caused at least one submit.
        expect(out.result).toBeGreaterThanOrEqual(1);
      },
      TEST_TIMEOUT_MS,
    );

    it(
      "dead-daemon recovery: force-kill + auto-respawn on next call + _note on replay (Fix D)",
      async () => {
        // SIGKILL + wait for Chromium child processes to actually exit
        // (they're our biggest source of left-behind state — stale
        // SingletonLock etc.). pkill-tree reaches children; the short
        // sleep gives the OS a tick to process the signal.
        await rawSandbox.process.executeCommand(
          "pkill -9 -f apex-pw-daemon.cjs 2>/dev/null; " +
            "pkill -9 chrom 2>/dev/null; " +
            "sleep 0.5; true",
        );

        let nav:
          | {
              success: boolean;
              url: string;
              title?: string;
              error?: string;
              _note?: string;
            }
          | undefined;
        let callErr: unknown;
        try {
          nav = await callDaemon<{
            success: boolean;
            url: string;
            title?: string;
            error?: string;
            _note?: string;
          }>(sandbox, "navigate", { url: "about:blank" });
        } catch (e) {
          callErr = e;
        }

        if (callErr || !nav?.success) {
          const logDump = await rawSandbox.process.executeCommand(
            "cat /tmp/apex-pw-daemon.log 2>/dev/null",
          );
          const psDump = await rawSandbox.process.executeCommand(
            "ps aux | grep -E 'node|chrom|apex' | grep -v grep",
          );
          const portDump = await rawSandbox.process.executeCommand(
            "echo 'PORT_FILE:'; cat /tmp/apex-pw-port 2>/dev/null; echo; echo 'LISTENERS:'; ss -ltn 2>/dev/null | head -20",
          );
          throw new Error(
            `post-kill navigate failed: ${callErr ? String(callErr) : nav?.error}\n` +
              `--- daemon log (full) ---\n${logDump.result}\n` +
              `--- ps ---\n${psDump.result}\n` +
              `--- port file + listeners ---\n${portDump.result}`,
          );
        }
        expect(nav.success).toBe(true);
        // Fix D: the replay path MUST inject `_note` so the agent knows
        // state was reset. Without it, agents waste steps guessing why
        // the page is blank (exactly what ses_24f3acb4 did at 12:00).
        expect(nav._note).toBeDefined();
        expect(nav._note).toMatch(/restart|reset|state/i);

        // Subsequent calls on the fresh daemon should NOT have _note
        // (only the replay-after-respawn gets it).
        const ev = await callDaemon<{
          success: boolean;
          result: number;
          _note?: string;
        }>(sandbox, "evaluate", { script: "1 + 1" });
        expect(ev.success).toBe(true);
        expect(ev.result).toBe(2);
        expect(ev._note).toBeUndefined();
      },
      TEST_TIMEOUT_MS,
    );
  },
);
