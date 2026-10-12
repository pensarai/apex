/**
 * Runtime-parity probe for `PerCommandShell`.
 *
 * Exercises happy / timeout / abort / cancel / large-output / failed-launcher
 * paths and asserts the same outcomes under Node and Bun:
 *   - Bun:   `bun scripts/validate-shell.ts`
 *   - Node:  `bun build --target node scripts/validate-shell.ts --outfile /tmp/validate-shell.js`
 *            then `node /tmp/validate-shell.js` (the bundle is self-contained
 *            stdlib — no tsx/loader needed).
 *
 * This catches the class of bugs where vitest (Node-only) tests pass but the
 * production Bun runtime behaves differently.
 *
 * Exits 0 if all cases pass under the current runtime, 1 otherwise.
 */
// Imports the executor module directly (stdlib + PerCommandShell only) so
// this probe stays self-contained and bundleable via
// `bun build --target node scripts/validate-shell.ts`.
import { PerCommandShell } from "../src/core/agents/offSecAgent/tools/perCommandShell";

interface Case {
  name: string;
  run: (shell: PerCommandShell) => Promise<{
    pass: boolean;
    detail: string;
  }>;
}

const RUNTIME =
  typeof (globalThis as { Bun?: unknown }).Bun !== "undefined" ? "bun" : "node";

const cases: Case[] = [
  {
    name: "happy",
    run: async (s) => {
      const r = await s.execute("echo hello-happy");
      const pass = r.exitCode === 0 && /hello-happy/.test(r.stdout);
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "fresh-per-invocation",
    run: async (s) => {
      await s.execute("export APEX_PARITY_LEAK=1");
      const r = await s.execute('echo "v=$APEX_PARITY_LEAK"');
      const pass = r.exitCode === 0 && r.stdout.trim() === "v=";
      return {
        pass,
        detail: `stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "timeout-with-partial",
    run: async (s) => {
      const r = await s.execute(
        "printf 'hit-1\\n'; printf 'hit-2\\n'; sleep 30",
        {
          timeoutSeconds: 1,
        },
      );
      const pass =
        r.exitCode === 124 &&
        r.timedOut === true &&
        r.stdout.includes("hit-1") &&
        r.stdout.includes("hit-2");
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "abort-with-partial",
    run: async (s) => {
      const ac = new AbortController();
      setTimeout(() => ac.abort(), 200);
      const r = await s.execute("printf 'abort-hit\\n'; sleep 30", {
        timeoutSeconds: 30,
        abortSignal: ac.signal,
      });
      const pass = r.exitCode === 130 && r.stdout.includes("abort-hit");
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "cancel-with-partial",
    run: async (s) => {
      const promise = s.execute("printf 'cancel-hit\\n'; sleep 30", {
        timeoutSeconds: 30,
      });
      setTimeout(() => s.cancelCurrentCommand(), 200);
      const r = await promise;
      const pass = r.exitCode === 130 && r.stdout.includes("cancel-hit");
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "large-output-completes",
    run: async (s) => {
      // 2 MiB: past the 1 MiB capture cap — the process must still complete
      // (never killed for volume) with a truthful truncation flag.
      const r = await s.execute("yes 'line' | head -c 2097152", {
        timeoutSeconds: 30,
      });
      const pass =
        r.exitCode === 0 &&
        r.stdoutTruncated === true &&
        r.stdout.length === 1024 * 1024;
      return {
        pass,
        detail: `exit=${r.exitCode} stdout.len=${r.stdout.length} truncated=${r.stdoutTruncated}`,
      };
    },
  },
  {
    name: "failed-launcher-sweeps-service",
    run: async (s) => {
      const r = await s.execute("bash -c 'sleep 30' > /dev/null 2>&1 & false", {
        timeoutSeconds: 10,
      });
      const pass = r.exitCode === 1 && r.cleanupUnconfirmed === false;
      return {
        pass,
        detail: `exit=${r.exitCode} unconfirmed=${r.cleanupUnconfirmed}`,
      };
    },
  },
  {
    name: "bare-wait-with-background-job",
    run: async (s) => {
      // No internal monitor exists: bare `wait` must see only user jobs.
      const r = await s.execute("sleep 0.2 & wait; printf finished", {
        timeoutSeconds: 10,
      });
      const pass = r.exitCode === 0 && r.stdout === "finished";
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "term-resistant-redirected-child-dies-at-settlement",
    run: async (s) => {
      // The critical process-group claim, under the real runtime: a
      // redirected-stdio child traps TERM and acknowledges readiness AFTER
      // installing the trap; abort kills the leader on TERM but settlement
      // must wait for the 3s SIGKILL and the group to be observed gone.
      const os = await import("node:os");
      const fs = await import("node:fs");
      const path = await import("node:path");
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "apex-parity-"));
      const pidFile = path.join(dir, "resistant.pid");
      const readyFile = path.join(dir, "resistant.ready");
      let childPid = 0;
      try {
        const ac = new AbortController();
        const pending = s.execute(
          'bash -c \'echo $$ > "$APEX_PID"; trap "" TERM; echo ready > "$APEX_READY"; sleep 60\' > /dev/null 2>&1 & while [ ! -f "$APEX_READY" ]; do sleep 0.02; done; sleep 30',
          {
            timeoutSeconds: 60,
            abortSignal: ac.signal,
            env: { APEX_PID: pidFile, APEX_READY: readyFile },
          },
        );
        const deadline = Date.now() + 5_000;
        while (!fs.existsSync(readyFile) && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 20));
        }
        const started = Date.now();
        ac.abort();
        const r = await pending;
        const elapsed = Date.now() - started;
        childPid = parseInt(fs.readFileSync(pidFile, "utf8").trim(), 10);

        const pass =
          r.exitCode === 130 &&
          r.cleanupUnconfirmed === false &&
          elapsed >= 2_500 &&
          elapsed < 6_000;
        // Confirm the child is actually dead via signal-0 probing.
        let dead = false;
        const probeDeadline = Date.now() + 5_000;
        while (Date.now() < probeDeadline) {
          try {
            process.kill(childPid, 0);
            await new Promise((r) => setTimeout(r, 25));
          } catch {
            dead = true;
            break;
          }
        }
        return {
          pass: pass && dead,
          detail: `exit=${r.exitCode} unconfirmed=${r.cleanupUnconfirmed} elapsed=${elapsed}ms childDead=${dead}`,
        };
      } finally {
        // Explicit cleanup even when the case fails.
        if (childPid) {
          try {
            process.kill(childPid, "SIGKILL");
          } catch {
            // already dead
          }
        }
        try {
          fs.rmSync(dir, { recursive: true, force: true });
        } catch {
          // already gone
        }
      }
    },
  },
  {
    name: "responsive-after-timeout",
    run: async (s) => {
      await s.execute("printf 'pre\\n'; sleep 30", { timeoutSeconds: 0.5 });
      const r = await s.execute("echo recovered", { timeoutSeconds: 5 });
      const pass = r.exitCode === 0 && /recovered/.test(r.stdout);
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "dispose-barrier-settles-active",
    run: async (s) => {
      const pending = s.execute("sleep 30");
      await new Promise((r) => setTimeout(r, 150));
      await s.dispose();
      const r = await pending;
      const pass = r.exitCode === 130;
      return { pass, detail: `exit=${r.exitCode}` };
    },
  },
];

async function main(): Promise<void> {
  console.log(`=== runtime: ${RUNTIME} ===`);
  let failed = 0;
  for (const c of cases) {
    const shell = new PerCommandShell();
    const start = Date.now();
    try {
      const { pass, detail } = await c.run(shell);
      const elapsed = Date.now() - start;
      const status = pass ? "PASS" : "FAIL";
      console.log(`[${status}] ${c.name} (${elapsed}ms): ${detail}`);
      if (!pass) failed++;
    } catch (err) {
      console.log(
        `[ERROR] ${c.name}: ${err instanceof Error ? err.message : String(err)}`,
      );
      failed++;
    } finally {
      await shell.dispose();
      // Brief pause so group teardown settles before the next case.
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  console.log(`=== ${failed === 0 ? "ALL PASS" : `${failed} FAILED`} ===`);
  process.exit(failed === 0 ? 0 : 1);
}

void main();
