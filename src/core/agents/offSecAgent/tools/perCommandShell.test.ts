import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

import { PerCommandShell } from "./perCommandShell";

// Real-process contract tests for the per-command executor: fresh shell and
// process group per invocation, curated environment, bounded capture, and a
// single terminating path whose settlement waits for the group to actually
// die. Every fixture is a real child; readiness is acknowledged via files
// the child writes after its signal handlers are installed.

describe("PerCommandShell — fresh invocation semantics", () => {
  const cleanup: Array<() => Promise<void> | void> = [];
  afterAll(async () => {
    for (const fn of cleanup) await fn();
  });

  const make = (opts?: { cwd?: string; env?: Record<string, string> }) => {
    const shell = new PerCommandShell(opts);
    cleanup.push(() => shell.dispose());
    return shell;
  };

  const fixtureDir = () => {
    const dir = mkdtempSync(join(tmpdir(), "apex-pcs-"));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    return dir;
  };

  it("runs each invocation in a fresh shell: cd/export/functions do not leak", async () => {
    const shell = make();

    const first = await shell.execute(
      "cd /tmp && export APEX_FRESH_LEAK=1 && pwd",
    );
    expect(first.exitCode).toBe(0);
    expect(first.stdout.trim()).toBe("/tmp");

    // Fresh invocation: cwd and env are back to the executor's defaults.
    const leakedCwd = await shell.execute("pwd");
    expect(leakedCwd.exitCode).toBe(0);
    expect(realpathSync(leakedCwd.stdout.trim())).toBe(
      realpathSync(process.cwd()),
    );

    const leakedEnv = await shell.execute('echo "v=$APEX_FRESH_LEAK"');
    expect(leakedEnv.stdout).toBe("v=\n");

    await shell.execute("apex_test_fn() { echo fn-ran; }; apex_test_fn");
    const leakedFn = await shell.execute("apex_test_fn 2>&1 || true");
    expect(leakedFn.stdout).not.toContain("fn-ran");
  });

  it("supports explicit cwd and per-invocation env, with per-call env overriding constructor extras", async () => {
    const dir = fixtureDir();
    const shell = make({
      cwd: process.cwd(),
      env: { APEX_BASE_VAR: "base" },
    });

    const inDir = await shell.execute("pwd", { cwd: dir });
    expect(inDir.exitCode).toBe(0);
    // bash's startup PWD is the physical working directory.
    expect(inDir.stdout.trim()).toBe(realpathSync(dir));

    const env = await shell.execute('echo "$APEX_BASE_VAR|$APEX_CALL_VAR"', {
      env: { APEX_CALL_VAR: "call", APEX_BASE_VAR: "overridden" },
    });
    expect(env.stdout).toBe("overridden|call\n");
  });

  it("never inherits arbitrary process env (infra credential exclusion)", async () => {
    process.env.APEX_TEST_INFRA_SECRET = "secret-value";
    try {
      const shell = make();
      const r = await shell.execute('echo "s=$APEX_TEST_INFRA_SECRET"');
      expect(r.stdout).toBe("s=\n");
    } finally {
      delete process.env.APEX_TEST_INFRA_SECRET;
    }
  });

  it("bare wait with background jobs completes naturally (no internal monitor)", async () => {
    const shell = make();
    const r = await shell.execute("sleep 0.2 & wait; printf finished");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe("finished");

    for (let i = 0; i < 3; i++) {
      const again = await shell.execute("sleep 0.1 & wait; printf done", {
        timeoutSeconds: 10,
      });
      expect(again.exitCode).toBe(0);
      expect(again.stdout).toBe("done");
    }
  });

  it("preserves exact stdout/stderr separation, CRLF bytes, and exit codes", async () => {
    const shell = make();
    const r = await shell.execute(
      "printf 'line-a\\r\\nline-b\\r\\n'; printf 'err-1\\r\\n' >&2; exit 7",
    );
    expect(r.exitCode).toBe(7);
    expect(r.stdout).toBe("line-a\r\nline-b\r\n");
    expect(r.stderr).toBe("err-1\r\n");
  });

  it("keeps a verbose process running past the capture cap and reports truncation", async () => {
    const dir = fixtureDir();
    const shell = make();
    // ~2 MiB of output — past the 1 MiB per-stream cap. Capture stays
    // prefix-bounded (discarded bytes never reappear); the producer is
    // proven to have COMPLETED via exit code and an independent sentinel.
    const r = await shell.execute(
      'yes "xxxxxxxx" | head -c 2097152; touch "$APEX_SENTINEL"',
      {
        timeoutSeconds: 30,
        env: { APEX_SENTINEL: join(dir, "completed.sentinel") },
      },
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdoutTruncated).toBe(true);
    expect(r.stdout.length).toBe(1024 * 1024);
    expect(r.stdout.startsWith("xxxxxxxx")).toBe(true);
    expect(existsSync(join(dir, "completed.sentinel"))).toBe(true);
  });

  it("delivers live stdout events via onData", async () => {
    const shell = make();
    const events: string[] = [];
    const r = await shell.execute("echo first; sleep 0.3; echo second", {
      timeoutSeconds: 10,
      onData: (chunk) => events.push(chunk),
    });
    expect(r.exitCode).toBe(0);
    expect(events.join("")).toContain("first");
    expect(events.join("")).toContain("second");
  });
});

describe("PerCommandShell — termination guarantees", () => {
  const cleanup: Array<() => Promise<void> | void> = [];
  afterAll(async () => {
    for (const fn of cleanup) await fn();
  });

  const make = (opts?: { cwd?: string; env?: Record<string, string> }) => {
    const shell = new PerCommandShell(opts);
    cleanup.push(() => shell.dispose());
    return shell;
  };

  const fixtureDir = () => {
    const dir = mkdtempSync(join(tmpdir(), "apex-pcs-term-"));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    return dir;
  };

  // Probe liveness with signal 0 until the pid is gone — "reported dead" is
  // not the same as actually dead.
  async function expectPidDead(pid: number, timeoutMs = 5_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        process.kill(pid, 0);
      } catch {
        return;
      }
      if (Date.now() > deadline) {
        throw new Error(`pid ${pid} still alive after ${timeoutMs}ms`);
      }
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  async function waitForFile(path: string, timeoutMs = 5_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!existsSync(path)) {
      if (Date.now() > deadline) {
        throw new Error(`fixture file never appeared: ${path}`);
      }
      await new Promise((r) => setTimeout(r, 20));
    }
  }

  function killOrphan(pidFile: string): void {
    try {
      const pid = parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      if (Number.isFinite(pid)) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // already dead
        }
      }
    } catch {
      // pidFile never written
    }
  }

  it("timeout kills a pure-builtin loop in the leader and returns partial capture", async () => {
    const shell = make();
    const started = Date.now();
    const r = await shell.execute("printf hit-1; while :; do :; done", {
      timeoutSeconds: 0.3,
    });
    const elapsed = Date.now() - started;

    expect(r.exitCode).toBe(124);
    expect(r.timedOut).toBe(true);
    expect(r.cleanupUnconfirmed).toBe(false);
    expect(r.stdout).toContain("hit-1");
    // TERM-responsive: settles fast, well inside the 3s grace.
    expect(elapsed).toBeLessThan(2_000);
  }, 10_000);

  it("caller abort kills the invocation and returns partial capture", async () => {
    const shell = make();
    const ac = new AbortController();
    const r = await shell.execute("printf abort-hit; sleep 30", {
      timeoutSeconds: 60,
      abortSignal: ac.signal,
      // Event-driven abort: fires once the partial output actually exists.
      onData: (chunk) => {
        if (chunk.includes("abort-hit")) ac.abort();
      },
    });
    expect(r.exitCode).toBe(130);
    expect(r.timedOut).toBe(false);
    expect(r.stdout).toContain("abort-hit");
    expect(r.stderr).toContain("aborted");
  }, 10_000);

  it("cancelCurrentCommand cancels the active invocation only", async () => {
    const shell = make();
    expect(shell.cancelCurrentCommand()).toBe(false);

    const pending = shell.execute("printf cancel-hit; sleep 30", {
      timeoutSeconds: 60,
      onData: (chunk) => {
        if (chunk.includes("cancel-hit")) {
          setTimeout(() => shell.cancelCurrentCommand(), 0);
        }
      },
    });
    const r = await pending;
    expect(r.exitCode).toBe(130);
    expect(r.stdout).toContain("cancel-hit");

    // A later invocation is unaffected by the cancelled one.
    const after = await shell.execute("printf recovered", {
      timeoutSeconds: 10,
    });
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toBe("recovered");
  }, 10_000);

  it("aborts a TERM-resistant descendant only after the SIGKILL escalation — group confirmed gone at settlement", async () => {
    const dir = fixtureDir();
    const shell = make();
    const pidFile = join(dir, "resistant.pid");
    const readyFile = join(dir, "resistant.ready");

    try {
      const ac = new AbortController();
      // The child writes its PID, installs the TERM trap, and only THEN
      // acknowledges readiness — the launcher holds the foreground until the
      // trap is guaranteed installed, so no fixed sleeps are needed.
      const pending = shell.execute(
        'bash -c \'echo $$ > "$APEX_PID"; trap "" TERM; echo ready > "$APEX_READY"; sleep 60\' > /dev/null 2>&1 & while [ ! -f "$APEX_READY" ]; do sleep 0.02; done; sleep 30',
        {
          timeoutSeconds: 60,
          abortSignal: ac.signal,
          env: { APEX_PID: pidFile, APEX_READY: readyFile },
        },
      );
      await waitForFile(readyFile);
      ac.abort();

      const started = Date.now();
      const r = await pending;
      const elapsed = Date.now() - started;

      expect(r.exitCode).toBe(130);
      expect(r.cleanupUnconfirmed).toBe(false);
      // TERM (ignored by the child) → leader dies on TERM → SIGKILL at 3s →
      // group gone. Settlement cannot precede the escalation.
      expect(elapsed).toBeGreaterThanOrEqual(2_500);
      expect(elapsed).toBeLessThan(5_000);

      const childPid = parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      expect(Number.isFinite(childPid)).toBe(true);
      await expectPidDead(childPid);
    } finally {
      killOrphan(pidFile);
    }
  }, 15_000);

  it("a completed nonzero exit sweeps its background children (failed launcher)", async () => {
    const dir = fixtureDir();
    const shell = make();
    const pidFile = join(dir, "failed.pid");
    const readyFile = join(dir, "failed.ready");

    try {
      const r = await shell.execute(
        'bash -c \'echo $$ > "$APEX_PID"; echo ready > "$APEX_READY"; sleep 60\' > /dev/null 2>&1 & while [ ! -f "$APEX_READY" ]; do sleep 0.02; done; false',
        {
          timeoutSeconds: 30,
          env: { APEX_PID: pidFile, APEX_READY: readyFile },
        },
      );
      expect(r.exitCode).toBe(1);
      expect(r.cleanupUnconfirmed).toBe(false);

      const servicePid = parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      expect(Number.isFinite(servicePid)).toBe(true);
      await expectPidDead(servicePid);
    } finally {
      killOrphan(pidFile);
    }
  }, 15_000);

  it("a successful launcher's redirected service survives, including an unrelated later timeout", async () => {
    const dir = fixtureDir();
    const shell = make();
    const pidFile = join(dir, "svc.pid");
    const readyFile = join(dir, "svc.ready");

    try {
      // The launcher waits for the service's readiness before returning, so
      // the PID file is guaranteed present at exit — no read races.
      const launch = await shell.execute(
        'bash -c \'echo $$ > "$APEX_PID"; echo ready > "$APEX_READY"; sleep 60\' > /dev/null 2>&1 & while [ ! -f "$APEX_READY" ]; do sleep 0.02; done; echo launched',
        {
          timeoutSeconds: 10,
          env: { APEX_PID: pidFile, APEX_READY: readyFile },
        },
      );
      expect(launch.exitCode).toBe(0);
      expect(launch.stdout).toBe("launched\n");

      const servicePid = parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      expect(Number.isFinite(servicePid)).toBe(true);
      expect(() => process.kill(servicePid, 0)).not.toThrow();

      // An unrelated later command that times out must not touch the service.
      const timeoutCmd = await shell.execute("sleep 30", {
        timeoutSeconds: 0.3,
      });
      expect(timeoutCmd.exitCode).toBe(124);
      expect(() => process.kill(servicePid, 0)).not.toThrow();

      // Explicit lifecycle by the test (the documented management path).
      process.kill(servicePid, "SIGKILL");
      await expectPidDead(servicePid);
      unlinkSync(pidFile);
    } finally {
      killOrphan(pidFile);
    }
  }, 15_000);

  it("an inherited-pipe child keeps the invocation pending until the deadline", async () => {
    const shell = make();
    const started = Date.now();
    // NOT redirected: the child holds our stdout pipe, so 'close' waits —
    // the deadline bounds it and the terminating path cleans the group.
    const r = await shell.execute("sleep 30 &", { timeoutSeconds: 0.3 });
    const elapsed = Date.now() - started;

    expect(r.exitCode).toBe(124);
    expect(r.cleanupUnconfirmed).toBe(false);
    expect(elapsed).toBeLessThan(2_000);
  }, 10_000);

  it("spawn failure resolves with the cause, not a hang", async () => {
    const shell = make();
    const started = Date.now();
    const r = await shell.execute("echo hello", {
      cwd: "/nonexistent/apex-pcs-cwd",
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("nonexistent");
    // Settles immediately — nothing was spawned, so no kill protocol runs.
    expect(Date.now() - started).toBeLessThan(2_000);
  }, 10_000);

  it("an already-aborted signal returns immediately without spawning work", async () => {
    const shell = make();
    const ac = new AbortController();
    ac.abort();
    const r = await shell.execute("echo should-not-run", {
      abortSignal: ac.signal,
    });
    expect(r.exitCode).toBe(130);
    expect(r.stderr).toContain("aborted");
  });

  it("dispose returns a bounded idempotent barrier that awaits the active invocation's settlement", async () => {
    const shell = new PerCommandShell();
    let output = "";
    const pending = shell.execute("printf dispose-hit; sleep 30", {
      onData: (chunk) => {
        output += chunk;
      },
    });
    // Process startup can exceed a fixed delay when the full suite is busy.
    try {
      await vi.waitFor(() => expect(output).toContain("dispose-hit"), {
        timeout: 5000,
      });
    } catch (error) {
      await shell.dispose();
      throw error;
    }

    const barrier = shell.dispose();
    const sameBarrier = shell.dispose();
    expect(sameBarrier).toBe(barrier);

    const r = await pending;
    expect(r.exitCode).toBe(130);
    expect(r.stdout).toContain("dispose-hit");

    // The barrier resolves after the (already bounded) settlement, and
    // repeat calls return the same cached wait.
    await barrier;
    await sameBarrier;

    const after = await shell.execute("echo after-dispose");
    expect(after.exitCode).toBe(1);
    expect(after.stderr).toContain("disposed");
  }, 10_000);

  it("FIFO-serializes concurrent invocations so cancel targets exactly one", async () => {
    const shell = make();
    const first = shell.execute("printf a; sleep 30", {
      timeoutSeconds: 60,
      onData: (chunk) => {
        if (chunk.includes("a")) {
          setTimeout(() => {
            cancelResult = shell.cancelCurrentCommand();
          }, 0);
        }
      },
    });
    let cancelResult: boolean | null = null;
    // Queued behind the first — must not start until the turn releases.
    const second = shell.execute("printf b-ok", { timeoutSeconds: 10 });

    const firstResult = await first;
    expect(cancelResult).toBe(true);
    expect(firstResult.exitCode).toBe(130);

    const secondResult = await second;
    expect(secondResult.exitCode).toBe(0);
    expect(secondResult.stdout).toBe("b-ok");
  }, 15_000);

  it("dispose barrier drains the FIFO tail — all queued calls settle before it resolves", async () => {
    const shell = new PerCommandShell();
    const active = shell.execute("sleep 30");
    // Counter attached to each queued execute promise — it must read 20 the
    // moment the barrier resolves; awaiting them later would mask an early
    // barrier. (The active invocation is asserted separately below.)
    let settledCount = 0;
    const queued = Array.from({ length: 20 }, (_, i) =>
      shell.execute(`echo queued-${i}`, { timeoutSeconds: 10 }).then((r) => {
        settledCount++;
        return r;
      }),
    );

    await new Promise((r) => setTimeout(r, 150));
    const barrier = shell.dispose();
    await barrier;

    // All 20 queued calls have already settled at barrier resolution (an
    // early dispose would read < 20); the active one is asserted separately.
    expect(settledCount).toBe(20);
    const activeResult = await active;
    expect(activeResult.exitCode).toBe(130);
    for (const q of queued) {
      const r = await q;
      expect(r.exitCode).toBe(1);
      expect(r.stderr).toContain("disposed");
    }
    await Promise.allSettled([active, ...queued]);
  }, 15_000);

  it("preserves the first terminal cause: a natural failure outruns a late deadline inside cleanup", async () => {
    const dir = fixtureDir();
    const shell = make();
    const pidFile = join(dir, "natural.pid");
    const readyFile = join(dir, "natural.ready");

    try {
      // Readiness-gated launcher: the command exits 7 AFTER its TERM-
      // resistant child is ready, so the natural failure enters the
      // multi-second cleanup well before the 0.3s deadline fires. The
      // reported cause must stay the natural exit code, not a timeout.
      const started = Date.now();
      const r = await shell.execute(
        'bash -c \'echo $$ > "$APEX_PID"; trap "" TERM; echo ready > "$APEX_READY"; sleep 60\' > /dev/null 2>&1 & while [ ! -f "$APEX_READY" ]; do sleep 0.02; done; exit 7',
        {
          timeoutSeconds: 0.3,
          env: { APEX_PID: pidFile, APEX_READY: readyFile },
        },
      );
      const elapsed = Date.now() - started;

      expect(r.exitCode).toBe(7);
      expect(r.timedOut).toBe(false);
      expect(r.cleanupUnconfirmed).toBe(false);
      expect(elapsed).toBeGreaterThanOrEqual(2_500);

      const childPid = parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      await expectPidDead(childPid);
    } finally {
      killOrphan(pidFile);
    }
  }, 15_000);

  it("an EPERM group probe stays unconfirmed — never claimed gone", async () => {
    const shell = make();
    // Mock ONLY the signal-0 group probes: they answer EPERM, which is
    // "unknown", never "gone". Real TERM/KILL signals pass through so the
    // actual child is still terminated.
    const realKill = process.kill.bind(process);
    const probeSpy = vi
      .spyOn(process, "kill")
      .mockImplementation((pid, signal) => {
        if (signal === 0) {
          throw Object.assign(new Error("probe EPERM"), { code: "EPERM" });
        }
        return realKill(pid, signal);
      });
    try {
      const started = Date.now();
      const r = await shell.execute("printf probe-hit; sleep 30", {
        timeoutSeconds: 0.3,
      });
      const elapsed = Date.now() - started;

      expect(r.exitCode).toBe(124);
      expect(r.stdout).toContain("probe-hit");
      // The probe could never confirm the group — surfaced, not assumed.
      expect(r.cleanupUnconfirmed).toBe(true);
      expect(r.stderr).toContain("cleanup unconfirmed");
      // Bounded: TERM grace + KILL + ack window, never a hang.
      expect(elapsed).toBeLessThan(6_000);
    } finally {
      probeSpy.mockRestore();
    }
  }, 15_000);
});
