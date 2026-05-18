/**
 * Runtime-parity probe for `PersistentShell`.
 *
 * Exercises happy / timeout / abort / cancel / large-output / responsive-after
 * paths and asserts the same outcomes under Node (`node --import tsx
 * scripts/validate-shell.ts`) and Bun (`bun scripts/validate-shell.ts`).
 *
 * This catches the class of bugs where vitest (Node-only) tests pass but
 * the production Bun runtime drops bytes, e.g. issue #644.
 *
 * Exits 0 if all cases pass under the current runtime, 1 otherwise.
 */
import { PersistentShell } from "../src/core/agents/offSecAgent";

interface Case {
  name: string;
  run: (shell: PersistentShell) => Promise<{
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
      const r = await s.execute("echo hello-happy", 5);
      const pass = r.exitCode === 0 && /hello-happy/.test(r.stdout);
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "timeout-with-partial",
    run: async (s) => {
      const r = await s.execute(
        `printf 'hit-1\\n'; printf 'hit-2\\n'; sleep 30`,
        1,
      );
      const pass =
        r.exitCode === 124 &&
        r.stdout.includes("hit-1") &&
        r.stdout.includes("hit-2") &&
        !/__APEX_[0-9a-f]+__/.test(r.stdout);
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
      const r = await s.execute(
        `printf 'abort-hit\\n'; sleep 30`,
        30,
        undefined,
        ac.signal,
      );
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
      let promise: Promise<{ exitCode: number; stdout: string }> | null = null;
      // Kick off a long-running command, then call cancelCurrentCommand
      // from a 200ms timer.
      promise = s.execute(`printf 'cancel-hit\\n'; sleep 30`, 30);
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
    name: "large-output-timeout",
    run: async (s) => {
      const r = await s.execute(
        `for i in $(seq 1 4000); do printf 'line-%05d\\n' $i; done; sleep 30`,
        1,
      );
      const pass =
        r.exitCode === 124 &&
        r.stdout.includes("line-00001") &&
        r.stdout.includes("line-04000");
      return {
        pass,
        detail: `exit=${r.exitCode} stdout.len=${r.stdout.length}`,
      };
    },
  },
  {
    name: "sigterm-resistant",
    run: async (s) => {
      const r = await s.execute(
        `bash -c "trap '' TERM; printf 'survived-trap\\n'; sleep 30"`,
        1,
      );
      const pass = r.exitCode === 124 && r.stdout.includes("survived-trap");
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
  {
    name: "responsive-after-timeout",
    run: async (s) => {
      // Run a timeout first to put the shell through a kill path, then
      // verify it still answers.
      await s.execute(`printf 'pre\\n'; sleep 30`, 1);
      const r = await s.execute("echo recovered", 5);
      const pass = r.exitCode === 0 && /recovered/.test(r.stdout);
      return {
        pass,
        detail: `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`,
      };
    },
  },
];

async function main(): Promise<void> {
  console.log(`=== runtime: ${RUNTIME} ===`);
  let failed = 0;
  for (const c of cases) {
    const shell = new PersistentShell();
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
      shell.dispose();
      // Brief pause so dispose's process-group teardown can settle
      // before the next case constructs a fresh shell.
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  console.log(`=== ${failed === 0 ? "ALL PASS" : `${failed} FAILED`} ===`);
  process.exit(failed === 0 ? 0 : 1);
}

void main();
