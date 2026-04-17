import { afterEach, describe, expect, it } from "vitest";

import { PersistentShell } from "./persistentShell";

/**
 * These tests document and reproduce the "shell eventually stops responding"
 * class of bugs in PersistentShell. They are written as hang-repros: each test
 * exercises a scenario a long-running pentest agent realistically hits, and
 * asserts the contract the tool advertises.
 *
 * Several of these are EXPECTED TO FAIL against the current implementation.
 * They are intentionally left failing so the bugs cannot be silently
 * re-introduced once fixed. They use `it.fails(...)` so the suite stays green
 * while clearly flagging the known-broken behavior.
 */
describe("PersistentShell — long-running stability", () => {
  const shells: PersistentShell[] = [];
  const make = () => {
    const s = new PersistentShell();
    shells.push(s);
    return s;
  };

  afterEach(() => {
    while (shells.length) {
      try {
        shells.pop()?.dispose();
      } catch {
        // ignore
      }
    }
  });

  it("basic smoke: sequential commands return quickly", async () => {
    const shell = make();
    const r1 = await shell.execute("echo one", 5);
    expect(r1.exitCode).toBe(0);
    expect(r1.stdout).toContain("one");

    const r2 = await shell.execute("echo two", 5);
    expect(r2.exitCode).toBe(0);
    expect(r2.stdout).toContain("two");
  });

  /**
   * Repro #1 — Stdin hijack by a child process.
   *
   * The shell's stdin pipe is shared with every child bash spawns. A command
   * that reads from stdin (cat/ssh/sudo/python/mysql/read/...) will consume
   * bytes that were meant for bash's own command parsing.
   *
   * After this command is killed by the timeout path, subsequent
   * `execute()` calls should still work — but in practice they hang until
   * their own timeout because:
   *   - cat consumed part of bash's command buffer, or
   *   - bash is still mid-way through the previous wrapped block.
   *
   * Agents hit this constantly after many commands because the model is
   * prone to running things like `sudo ...` or `ssh ...` mid-pentest.
   */
  it.fails(
    "stays responsive after a command that reads from stdin is killed",
    async () => {
      const shell = make();

      const warm = await shell.execute("echo warm", 5);
      expect(warm.exitCode).toBe(0);

      // `cat` with no args blocks reading stdin. It inherits fd 0 from bash,
      // which is the same pipe PersistentShell writes commands into.
      const hung = await shell.execute("cat", 2);
      expect(hung.exitCode).toBe(124);

      // Subsequent command should return within a normal timeout.
      const after = await shell.execute("echo after-cat", 5);
      expect(after.exitCode).toBe(0);
      expect(after.stdout).toContain("after-cat");
    },
    20_000,
  );

  /**
   * Repro #2 — Process-group leak after timeout.
   *
   * `pkill -TERM -P <bashpid>` only reaps direct children of bash. For a
   * pipeline (`a | b | c`) the workers are grandchildren of bash (children
   * of the subshell), so they survive the timeout, become orphans, and keep
   * their inherited fd 1 — feeding Repro #3 below.
   *
   * After the timeout, we should see no descendant processes still holding
   * the shell's stdout pipe.
   */
  it.fails(
    "cleans up pipeline grandchildren when a command times out",
    async () => {
      const shell = make();
      // Prime the shell so we have a stable pid to probe.
      await shell.execute("echo prime", 5);
      const bashPid = (shell as unknown as { proc: { pid: number } }).proc.pid;
      expect(bashPid).toBeGreaterThan(0);

      // Pipeline: sleep is a grandchild of bash (child of the subshell).
      const timed = await shell.execute("sleep 30 | cat", 2);
      expect(timed.exitCode).toBe(124);

      // Give pkill + the 1s drain window a moment.
      await new Promise((r) => setTimeout(r, 1_500));

      const { spawnSync } = await import("child_process");
      const out = spawnSync(
        "ps",
        ["--ppid", String(bashPid), "-o", "pid=,comm="],
        { encoding: "utf8" },
      );
      const remaining = (out.stdout || "")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      // No direct bash children should remain; none of them should be sleep.
      expect(remaining.find((l) => l.includes("sleep"))).toBeUndefined();
    },
    20_000,
  );

  /**
   * Repro #3 — Output from a backgrounded command bleeds into the next
   * command's captured stdout.
   *
   * Background producers whose fd 1 wasn't redirected keep writing to bash's
   * stdout pipe. Between `execute()` calls the `data` listener is removed,
   * so buffered bytes land on the *next* command's `stdout` accumulator.
   * The caller sees output they never asked for, and sufficiently chatty
   * producers eventually push past the 5MB MAX_BUFFER and trip the
   * "stdout = stdout.substring(stdout.length - MAX_BUFFER)" truncation —
   * which, if a marker ever lands near the start, silently drops it and
   * we wait for a marker that will never appear.
   */
  it.fails(
    "does not leak background-process output into the next command's stdout",
    async () => {
      const shell = make();

      // Background a generator whose fd 1 is NOT redirected. This is the
      // realistic footgun (`nmap -v &` without `>out.log 2>&1 &`).
      const bg = await shell.execute(
        "( while :; do echo spam-$RANDOM; done ) &",
        3,
      );
      expect(bg.exitCode).toBe(0);

      // Give the spammer a moment to write into the pipe.
      await new Promise((r) => setTimeout(r, 500));

      const quick = await shell.execute("echo fast", 3);

      // Clean up the spammer before asserting so the shell is reusable.
      await shell.execute(
        "kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; true",
        3,
      );

      expect(quick.exitCode).toBe(0);
      // The next command should see ONLY its own output, not a mountain of
      // spam from the orphaned background loop.
      expect(quick.stdout.includes("spam-")).toBe(false);
    },
    20_000,
  );

  /**
   * Repro #4 — `cd` does not persist across commands, contradicting the
   * tool description that claims "environment variables, working directory
   * (cd), and background processes survive across calls". Each command is
   * wrapped in `( ... )` which runs in a subshell, so `cd` only affects the
   * subshell.
   *
   * Not directly a "hang" cause, but it's the same root as the stability
   * problems — the subshell wrapper hides state from the outer shell.
   */
  it.fails("persists cd across commands (documented contract)", async () => {
    const shell = make();
    const mk = await shell.execute(
      "mkdir -p /tmp/apex-persistent-shell-test-2ef1",
      5,
    );
    expect(mk.exitCode).toBe(0);

    const cd = await shell.execute(
      "cd /tmp/apex-persistent-shell-test-2ef1",
      5,
    );
    expect(cd.exitCode).toBe(0);

    const pwd = await shell.execute("pwd", 5);
    expect(pwd.exitCode).toBe(0);
    expect(pwd.stdout).toContain("/tmp/apex-persistent-shell-test-2ef1");
  });

  /**
   * Repro #5 — The cumulative "agent ran for a while" simulation.
   *
   * After many commands — some of which read stdin, some of which
   * background processes without redirecting fd 1, some of which use
   * pipelines that time out — a trivial `echo` should still come back
   * within its timeout. This is the end-state the user described:
   * "after some time commands will just hang and timeout".
   */
  it.fails(
    "stays responsive after a mixed workload of 30 commands",
    async () => {
      const shell = make();

      for (let i = 0; i < 10; i++) {
        const r = await shell.execute(`echo iter-${i}`, 5);
        expect(r.exitCode).toBe(0);
      }

      // A couple of stdin-reading commands (get killed by timeout).
      for (let i = 0; i < 2; i++) {
        await shell.execute("cat", 2);
      }

      // A background spammer.
      await shell.execute("while :; do echo s-$RANDOM; done &", 3);

      // A timing-out pipeline.
      await shell.execute("sleep 10 | cat", 2);

      // Final probe: trivial echo must succeed quickly.
      const start = Date.now();
      const final = await shell.execute("echo final", 5);
      const elapsed = Date.now() - start;

      expect(final.exitCode).toBe(0);
      expect(final.stdout).toContain("final");
      expect(elapsed).toBeLessThan(3_000);
    },
    60_000,
  );
});
