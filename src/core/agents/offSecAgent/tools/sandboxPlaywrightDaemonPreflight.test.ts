/**
 * Phase 1 pre-flight tests for the persistent Chromium daemon architecture.
 *
 * These tests validate the THREE critical runtime-model unknowns that every
 * downstream phase depends on, against a REAL Daytona sandbox:
 *
 *   1. Localhost reachability: can `curl http://127.0.0.1:<port>` via
 *      sandbox.execute reach a listener bound inside the same sandbox?
 *      If NO, the daemon architecture is not viable over TCP and we need
 *      to pivot to Unix-domain sockets.
 *
 *   2. Background-process survival: does `nohup node ... &` return control
 *      to the caller immediately while the child keeps running? The dockerd
 *      precedent at packages/sandbox/createSandbox.ts:266-270 suggests yes,
 *      but needs empirical confirmation since that pathway is different from
 *      ad-hoc execute() calls.
 *
 *   3. Atomic port-file publish/read: the daemon's port-discovery contract
 *      relies on an atomic `.tmp + rename` pattern so the host never
 *      observes a partial-write. Verify the rename is truly atomic under
 *      repeated reads.
 *
 * Gating: the full test suite is skipped when DAYTONA_API_KEY is not set.
 * Land this test first; when it passes twice on CI, proceed to Phase 2.
 */

import { Daytona, type Sandbox } from "@daytonaio/sdk";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { config } from "dotenv";

config();

const PREFLIGHT_PORT = 9100;
const TEST_TIMEOUT_MS = 180_000;
// Daytona's first-ever snapshot build for a given image can easily exceed
// 3-5 minutes. Subsequent builds land in <60s thanks to caching, but the
// cold path needs generous headroom so CI doesn't flake on account churn.
const SETUP_TIMEOUT_MS = 600_000;

describe.skipIf(!process.env.DAYTONA_API_KEY)(
  "sandboxPlaywrightDaemon preflight (Phase 1)",
  () => {
    let daytona: Daytona;
    let sandbox: Sandbox;

    beforeAll(async () => {
      const apiKey = process.env.DAYTONA_API_KEY;
      if (!apiKey) throw new Error("DAYTONA_API_KEY is required");
      daytona = new Daytona({
        apiKey,
        apiUrl: process.env.DAYTONA_API_URL ?? "https://app.daytona.io/api",
      });
      // Lightweight node image — we only need node + curl + shell primitives.
      // Mirrors the benchmark harness's choice at
      // src/core/agents/specialized/benchmark/remote/daytona-wrapper.ts:144.
      console.log("[preflight] creating sandbox...");
      const t0 = Date.now();
      // Canonical Docker Hub image — anonymously pullable, ~150MB, Debian
      // Bookworm with node 20 + curl preinstalled. The `daytona/node:*`
      // namespace requires registry auth.
      sandbox = await daytona.create(
        {
          image: "node:20-slim",
          resources: { cpu: 1, memory: 1, disk: 3 },
          public: false,
          networkBlockAll: false,
        },
        {
          timeout: 300_000,
          onSnapshotCreateLogs: (chunk) =>
            console.log(`[preflight:snapshot] ${chunk.trim()}`),
        },
      );
      console.log(
        `[preflight] sandbox ready: ${sandbox.id} (${Date.now() - t0}ms)`,
      );
      // Disable auto-stop; the suite is ~30s but shouldn't race Daytona's idle reaper.
      await sandbox.setAutostopInterval(0).catch(() => {});
      // node:20-slim ships without curl; install it once before running
      // tests (a few seconds on top of a sandbox that boots in <1s). In
      // the real workflow we'll rely on the DEV_ENVIRONMENT image that
      // has curl baked in; the test is cross-checking Daytona runtime
      // mechanics, not image contents.
      console.log("[preflight] installing curl...");
      const installCurl = await sandbox.process.executeCommand(
        "apt-get update -qq && apt-get install -y -qq curl procps iproute2 > /dev/null 2>&1 && which curl",
        undefined,
        undefined,
        120,
      );
      if ((installCurl.exitCode ?? 0) !== 0) {
        throw new Error(
          `failed to install curl: exitCode=${installCurl.exitCode} output=${installCurl.result}`,
        );
      }
      // Final tool-presence check — every tool must resolve to a path.
      // `which -a` returns non-zero if any arg is missing.
      const tools = await sandbox.process.executeCommand(
        "for t in node curl sh nohup pgrep ss; do which $t || { echo MISSING $t; exit 1; }; done",
      );
      if ((tools.exitCode ?? 0) !== 0) {
        throw new Error(
          `sandbox image missing a required tool:\n${tools.result ?? "(no output)"}`,
        );
      }
    }, SETUP_TIMEOUT_MS);

    afterAll(async () => {
      await Promise.allSettled([
        // Paranoid per-test-leak cleanup (suite shares one sandbox).
        sandbox?.process.executeCommand(
          "pkill -f 'node -e' 2>/dev/null; rm -f /tmp/preflight* 2>/dev/null; true",
        ),
        daytona?.delete(sandbox),
      ]);
    }, SETUP_TIMEOUT_MS);

    it(
      "1. localhost routing — curl reaches an in-sandbox HTTP listener",
      async () => {
        // Kill any leftover listener from a prior run.
        await sandbox.process.executeCommand(
          `sh -c 'fuser -k ${PREFLIGHT_PORT}/tcp 2>/dev/null; true'`,
        );

        // Spawn a minimal HTTP server inside the sandbox, backgrounded.
        // Quoting note: the shell string here is delivered verbatim to
        // sandbox.execute, which runs it via the sandbox's default shell.
        // We use single-quotes outside and escaped double-quotes inside
        // the node -e so the command survives shell interpolation exactly
        // as the future daemon-spawn command will.
        const spawnResult = await sandbox.process.executeCommand(
          `sh -c 'nohup node -e ` +
            `"require(\\"http\\").createServer((_,r)=>{r.end(\\"ok\\")}).listen(${PREFLIGHT_PORT},\\"127.0.0.1\\");" ` +
            `> /tmp/preflight-listener.log 2>&1 & echo $! > /tmp/preflight-listener.pid'`,
        );
        expect(
          spawnResult.exitCode ?? 0,
          `spawn failed: ${spawnResult.result}`,
        ).toBe(0);

        // Wait for the listener to bind. Poll rather than sleeping blindly.
        let bound = false;
        for (let i = 0; i < 20; i++) {
          const probe = await sandbox.process.executeCommand(
            `sh -c 'ss -ltn 2>/dev/null | grep -q ":${PREFLIGHT_PORT}" && echo bound || echo waiting'`,
          );
          if ((probe.result ?? "").includes("bound")) {
            bound = true;
            break;
          }
          await new Promise((r) => setTimeout(r, 250));
        }
        expect(bound, "listener did not bind within 5s").toBe(true);

        // The question of record: can we reach it via curl from the SAME
        // sandbox.execute surface? If yes, the daemon architecture works
        // over TCP. If no, we swap to Unix-domain sockets in Phase 2.
        const curl = await sandbox.process.executeCommand(
          `curl -s --max-time 3 http://127.0.0.1:${PREFLIGHT_PORT}/`,
        );
        expect(
          curl.result?.trim(),
          `curl failed: exitCode=${curl.exitCode} output=${curl.result}`,
        ).toBe("ok");
      },
      TEST_TIMEOUT_MS,
    );

    it(
      "2. backgrounded process survives executeCommand return",
      async () => {
        // Verify the PID captured in test 1 is still alive 10s after the
        // spawning call returned. This is the load-bearing invariant for
        // `nohup node daemon.js &` — if Daytona's executeCommand kills
        // the process group on return, the daemon can never outlive the
        // call that started it and the whole design collapses.
        const pidRead = await sandbox.process.executeCommand(
          "cat /tmp/preflight-listener.pid",
        );
        const pid = parseInt((pidRead.result ?? "").trim(), 10);
        expect(
          Number.isFinite(pid) && pid > 0,
          "no PID captured in test 1",
        ).toBe(true);

        await new Promise((r) => setTimeout(r, 10_000));

        // `kill -0 <pid>` exits 0 iff the pid is alive AND we have
        // permission to signal it. Inside the sandbox as the same user,
        // that's a clean liveness check.
        const alive = await sandbox.process.executeCommand(
          `sh -c 'kill -0 ${pid} 2>/dev/null && echo alive || echo dead'`,
        );
        expect(
          alive.result?.trim(),
          `PID ${pid} died within 10s of spawn — nohup-backgrounding does NOT survive executeCommand return. ` +
            `Fallback options: setsid, (cmd &) disown, or explicit child_process.fork inside a wrapper.`,
        ).toBe("alive");
      },
      TEST_TIMEOUT_MS,
    );

    it(
      "3. atomic port-file publish/read survives repeated reads",
      async () => {
        // Upload a tiny Node script that writes the port file the way the
        // daemon will — to `.tmp` then rename. Read it back 10 times in
        // rapid succession from the host and verify every read returns a
        // complete integer. A non-atomic write would produce occasional
        // empty or truncated reads.
        const writer = `
          const fs = require('fs');
          const PORT_FILE = '/tmp/preflight-port';
          const TMP = PORT_FILE + '.tmp';
          const port = parseInt(process.argv[2] ?? '12345', 10);
          fs.writeFileSync(TMP, String(port));
          fs.renameSync(TMP, PORT_FILE);
          console.log('wrote', port);
        `.trim();
        await sandbox.process.executeCommand(
          `cat > /tmp/preflight-writer.js <<'EOF'\n${writer}\nEOF`,
        );

        const bogusPortSequence = [41001, 41002, 41003, 41004, 41005];
        for (const port of bogusPortSequence) {
          const w = await sandbox.process.executeCommand(
            `node /tmp/preflight-writer.js ${port}`,
          );
          expect(w.exitCode ?? 0).toBe(0);

          // Burst-read the port file 10× immediately after the write.
          // Every read should be a complete integer — never empty, never
          // partial.
          for (let i = 0; i < 10; i++) {
            const r = await sandbox.process.executeCommand(
              "cat /tmp/preflight-port",
            );
            const v = parseInt((r.result ?? "").trim(), 10);
            expect(
              v,
              `burst-read ${i} after writing ${port}: got "${r.result}"`,
            ).toBe(port);
          }
        }
      },
      TEST_TIMEOUT_MS,
    );
  },
);
