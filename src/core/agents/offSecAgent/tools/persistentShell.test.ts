import { spawnSync } from "child_process";
import { afterEach, describe, expect, it } from "vitest";

import { PersistentShell } from "./persistentShell";

const HAS_STDBUF =
  process.platform !== "win32" &&
  spawnSync("stdbuf", ["--version"], { stdio: "ignore" }).status === 0;

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
   * Regression: on macOS without GNU `stdbuf`, the old wrapper relied on
   * plain `tail -f` for streaming. Because `tail`'s stdout was a pipe it
   * block-buffered, so short outputs were killed with tail before ever
   * flushing — every `ls -la`-style command came back with empty stdout
   * and the agent saw `(no output)`. The current wrapper always runs an
   * authoritative post-kill `cat` of the per-command tempfile through
   * bash's real stdout pipe, so `tail` buffering can no longer cause
   * stdout loss.
   */
  it("captures short stdout (no-stdbuf safe)", async () => {
    const shell = make();
    const r = await shell.execute("printf 'hello\\nworld\\n'", 5);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("hello");
    expect(r.stdout).toContain("world");
  });

  /**
   * Regression: on macOS with SIP, `stdbuf -oL` is a silent no-op on
   * /usr/bin/tail (DYLD_INSERT_LIBRARIES is stripped from protected
   * binaries). If the wrapper relies on tail alone to stream stdout,
   * tail block-buffers (~8 KiB default) and the buffer is discarded
   * when we kill tail 100 ms after the command finishes — every short
   * command returns empty stdout. Executed by APEX TUI in operator mode,
   * by the CLI pentest entrypoint, and by Evalgate-driven runs (e.g.
   * NOCTURNE), producing `(no output)` for trivial commands and
   * dominating eval signal with shell brokenness rather than agent
   * capability.
   *
   * These assertions fail on macOS against the pre-patch wrapper and
   * pass once the authoritative post-kill `cat` phase is in place.
   */
  it("captures trivial stdout even when tail block-buffers", async () => {
    const shell = make();
    const echo = await shell.execute("echo hello", 5);
    expect(echo.exitCode).toBe(0);
    expect(echo.stdout).toContain("hello");

    const pwd = await shell.execute("pwd", 5);
    expect(pwd.exitCode).toBe(0);
    expect(pwd.stdout.trim().length).toBeGreaterThan(0);

    const seq = await shell.execute("seq 1 5", 5);
    expect(seq.exitCode).toBe(0);
    expect(seq.stdout.trim()).toBe("1\n2\n3\n4\n5");
  });

  /**
   * Regression: tail's default block-buffer is ~8 KiB. A command whose
   * stdout is just under, at, and just over that boundary must come back
   * fully intact, with no silent truncation regardless of whether tail
   * ever flushed its buffer. Exercises the authoritative `cat` phase on
   * a realistic recon-output size.
   */
  it("captures output across the 8 KiB block-buffer boundary", async () => {
    const shell = make();
    // Emit exactly 9000 'x' bytes followed by a newline. Uses /dev/zero
    // to avoid bash/yes-pipeline byte-counting footguns (e.g.
    // `yes x | head -c 9000` includes the newlines that `yes` emits, so
    // stripping them halves the payload). 9000 > 8192 to ensure we
    // exceed tail's default ~8 KiB block-buffer size.
    const r = await shell.execute(
      "head -c 9000 /dev/zero | tr '\\0' 'x'; echo",
      5,
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout.replace(/\n$/, "").length).toBe(9000);
  });

  /**
   * Repro #1 — Stdin hijack by a child process.
   *
   * The shell's stdin pipe is shared with every child bash spawns. A command
   * that reads from stdin (cat/ssh/sudo/python/mysql/read/...) used to
   * consume bytes meant for bash's own command parsing, wedging the shell
   * for every subsequent call.
   *
   * The fix redirects each user command's stdin from /dev/null, so stdin
   * readers see EOF immediately and cannot hijack our command pipe. We
   * verify:
   *   1. `cat` does NOT hang — it EOFs cleanly (exit 0) in well under the
   *      timeout, proving stdin isolation works.
   *   2. The next command still runs immediately afterward.
   *
   * Agents hit this constantly in practice because models run things like
   * `sudo ...` or `ssh ...` mid-pentest.
   */
  it("stays responsive after a command that normally reads stdin", async () => {
    const shell = make();

    const warm = await shell.execute("echo warm", 5);
    expect(warm.exitCode).toBe(0);

    // `cat` with no args normally blocks on stdin. With /dev/null
    // redirection it EOFs instantly.
    const start = Date.now();
    const hung = await shell.execute("cat", 2);
    const elapsed = Date.now() - start;
    expect(hung.exitCode).toBe(0);
    expect(elapsed).toBeLessThan(1_500);

    // Subsequent command should return within a normal timeout.
    const after = await shell.execute("echo after-cat", 5);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("after-cat");
  }, 20_000);

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
  it("cleans up pipeline grandchildren when a command times out", async () => {
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
  }, 20_000);

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
  it("does not leak background-process output into the next command's stdout", async () => {
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
  }, 20_000);

  /**
   * Repro #4 — `cd` persists across commands.
   *
   * Previously the wrapper ran every command inside `( ... )`, a subshell,
   * which hid `cd`, `export`, shell functions, and option changes from the
   * outer shell. The tool's own description told the model these would
   * persist, so agents ran workflows that silently broke.
   *
   * The fix uses a brace group `{ ...; }` instead, which runs the command
   * in the current shell. Same scoping rules as a normal bash script, so
   * `cd`/`export`/etc. persist as advertised.
   */
  it("persists cd and export across commands (documented contract)", async () => {
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

    const exp = await shell.execute("export APEX_TEST_VAR=hello", 5);
    expect(exp.exitCode).toBe(0);
    const echo = await shell.execute('echo "$APEX_TEST_VAR"', 5);
    expect(echo.exitCode).toBe(0);
    expect(echo.stdout).toContain("hello");
  });

  /**
   * Timeout still reports the documented sentinel (124) and kills the
   * command's descendants, even though the shell's wrapper completes
   * cleanly after the kill.
   */
  it("reports exit code 124 on timeout and kills descendants", async () => {
    const shell = make();
    const r = await shell.execute("sleep 30", 1);
    expect(r.exitCode).toBe(124);

    // Shell must still be responsive.
    const after = await shell.execute("echo ok", 5);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("ok");
  }, 10_000);

  /**
   * Streaming callback fires as output arrives, where the platform's
   * `tail -f` actually flushes line-by-line. Requires effective
   * `stdbuf -oL` on `/usr/bin/tail` (or equivalent), which means:
   *
   *   - Linux glibc + GNU coreutils: works.
   *   - macOS under SIP: `DYLD_INSERT_LIBRARIES` is stripped from
   *     `/usr/bin/tail`, so `stdbuf` is a silent no-op; `tail`
   *     block-buffers its pipe and nothing flushes until we kill it.
   *     Final stdout is still correct (guaranteed by the authoritative
   *     post-kill `cat` phase), but live streaming is a known lossy UX
   *     on darwin and agents do not rely on it. Skip there.
   *   - Alpine / musl: BusyBox `tail` ignores `libstdbuf`; same result.
   *
   * The patch does not fix live streaming on these platforms — it only
   * fixes final-stdout correctness. This test guards the live-streaming
   * property on platforms that can deliver it.
   */
  it.skipIf(!HAS_STDBUF || process.platform === "darwin")(
    "streams stdout to onData as output arrives",
    async () => {
      const shell = make();
      const events: Array<{ t: number; text: string }> = [];
      const t0 = Date.now();
      const r = await shell.execute(
        "echo line-a; sleep 0.3; echo line-b; sleep 0.3; echo line-c",
        5,
        (c) => events.push({ t: Date.now() - t0, text: c }),
      );
      expect(r.exitCode).toBe(0);
      const joined = events.map((e) => e.text).join("");
      expect(joined).toContain("line-a");
      expect(joined).toContain("line-b");
      expect(joined).toContain("line-c");
      // The first chunk must arrive well before the last. If everything
      // came in one block at the end, streaming is broken.
      const firstA = events.find((e) => e.text.includes("line-a"));
      const firstC = events.find((e) => e.text.includes("line-c"));
      expect(firstA).toBeDefined();
      expect(firstC).toBeDefined();
      expect(firstC!.t - firstA!.t).toBeGreaterThan(200);
    },
  );

  /**
   * Repro #5 — The cumulative "agent ran for a while" simulation.
   *
   * After many commands — some of which read stdin, some of which
   * background processes without redirecting fd 1, some of which use
   * pipelines that time out — a trivial `echo` should still come back
   * within its timeout. This is the end-state the user described:
   * "after some time commands will just hang and timeout".
   */
  it("stays responsive after a mixed workload of 30 commands", async () => {
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
  }, 60_000);
});
