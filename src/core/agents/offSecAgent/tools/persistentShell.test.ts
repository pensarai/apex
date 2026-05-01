import { spawnSync } from "child_process";
import { afterEach, describe, expect, it } from "vitest";

import { extractFallbackStdout, PersistentShell } from "./persistentShell";

const HAS_STDBUF =
  process.platform !== "win32" &&
  spawnSync("stdbuf", ["--version"], { stdio: "ignore" }).status === 0;

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

  it("captures short stdout (no-stdbuf safe)", async () => {
    const shell = make();
    const r = await shell.execute("printf 'hello\\nworld\\n'", 5);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("hello");
    expect(r.stdout).toContain("world");
  });

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

  it("captures output across the 8 KiB block-buffer boundary", async () => {
    const shell = make();
    // 9000 > 8192 to exceed tail's default block-buffer.
    const r = await shell.execute(
      "head -c 9000 /dev/zero | tr '\\0' 'x'; echo",
      5,
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout.replace(/\n$/, "").length).toBe(9000);
  });

  it("stays responsive after a command that normally reads stdin", async () => {
    const shell = make();

    const warm = await shell.execute("echo warm", 5);
    expect(warm.exitCode).toBe(0);

    // `cat` with no args normally blocks on stdin. With /dev/null it EOFs.
    const start = Date.now();
    const hung = await shell.execute("cat", 2);
    const elapsed = Date.now() - start;
    expect(hung.exitCode).toBe(0);
    expect(elapsed).toBeLessThan(1_500);

    const after = await shell.execute("echo after-cat", 5);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("after-cat");
  }, 20_000);

  it("cleans up pipeline grandchildren when a command times out", async () => {
    const shell = make();
    await shell.execute("echo prime", 5);
    const bashPid = (shell as unknown as { proc: { pid: number } }).proc.pid;
    expect(bashPid).toBeGreaterThan(0);

    // Pipeline: sleep is a grandchild of bash (child of the subshell).
    const timed = await shell.execute("sleep 30 | cat", 2);
    expect(timed.exitCode).toBe(124);

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
    expect(remaining.find((l) => l.includes("sleep"))).toBeUndefined();
  }, 20_000);

  it("does not leak background-process output into the next command's stdout", async () => {
    const shell = make();

    // Background a generator whose fd 1 is NOT redirected (`nmap -v &`).
    const bg = await shell.execute(
      "( while :; do echo spam-$RANDOM; done ) &",
      3,
    );
    expect(bg.exitCode).toBe(0);

    await new Promise((r) => setTimeout(r, 500));

    const quick = await shell.execute("echo fast", 3);

    await shell.execute(
      "kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; true",
      3,
    );

    expect(quick.exitCode).toBe(0);
    expect(quick.stdout.includes("spam-")).toBe(false);
  }, 20_000);

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

  it("reports exit code 124 on timeout and kills descendants", async () => {
    const shell = make();
    const r = await shell.execute("sleep 30", 1);
    expect(r.exitCode).toBe(124);

    const after = await shell.execute("echo ok", 5);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("ok");
  }, 10_000);

  it("does not leak nonce markers on timeout", async () => {
    const shell = make();
    const r = await shell.execute(`printf 'hello\\n'; sleep 10`, 1);
    expect(r.exitCode).toBe(124);
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
  }, 10_000);

  it("does not leak nonce markers on abort", async () => {
    const shell = make();
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 200);
    const r = await shell.execute(
      `printf 'hi\\n'; sleep 10`,
      30,
      undefined,
      ac.signal,
    );
    expect(r.exitCode).toBe(130);
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
  }, 10_000);

  // Live-streaming UX requires effective `stdbuf -oL` on tail. macOS/SIP
  // strips DYLD_INSERT_LIBRARIES from /usr/bin/tail, and BusyBox tail ignores
  // libstdbuf — final stdout is still correct (authoritative cat) but live
  // streaming is lossy on those platforms, so skip there.
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
      const firstA = events.find((e) => e.text.includes("line-a"));
      const firstC = events.find((e) => e.text.includes("line-c"));
      expect(firstA).toBeDefined();
      expect(firstC).toBeDefined();
      expect(firstC!.t - firstA!.t).toBeGreaterThan(200);
    },
  );

  it("does not cross-contaminate stdout across parallel execute() calls", async () => {
    const shell = make();
    const [a, b] = await Promise.all([
      shell.execute("echo apex-call-a-output", 5),
      shell.execute("echo apex-call-b-output", 5),
    ]);

    expect(a.exitCode).toBe(0);
    expect(b.exitCode).toBe(0);
    expect(a.stdout).toContain("apex-call-a-output");
    expect(a.stdout).not.toContain("apex-call-b-output");
    expect(b.stdout).toContain("apex-call-b-output");
    expect(b.stdout).not.toContain("apex-call-a-output");
    expect(a.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
    expect(b.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
  }, 15_000);

  it("does not cross-contaminate stderr across parallel execute() calls", async () => {
    const shell = make();
    const [a, b] = await Promise.all([
      shell.execute(">&2 echo apex-call-a-stderr", 5),
      shell.execute("echo apex-call-b-stdout", 5),
    ]);

    expect(a.exitCode).toBe(0);
    expect(b.exitCode).toBe(0);
    expect(a.stderr).toContain("apex-call-a-stderr");
    expect(b.stderr).not.toContain("apex-call-a-stderr");
    expect(b.stdout).toContain("apex-call-b-stdout");
  }, 15_000);

  it("isolates parallel-call timeouts (no marker or kill-message leakage)", async () => {
    const shell = make();
    const [timedOut, ok] = await Promise.all([
      shell.execute("sleep 30", 1),
      shell.execute("echo apex-after-timeout", 5),
    ]);

    expect(timedOut.exitCode).toBe(124);
    expect(timedOut.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);

    expect(ok.exitCode).toBe(0);
    expect(ok.stdout).toContain("apex-after-timeout");
    expect(ok.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
    expect(ok.stderr).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
    // Bash's job-control kill messages from the timed-out sibling must not
    // appear on the surviving call's stderr.
    expect(ok.stderr).not.toMatch(/Terminated|Killed/);
  }, 15_000);

  it("preserves FIFO ordering for parallel execute() calls", async () => {
    const shell = make();
    const results = await Promise.all([
      shell.execute("echo 1", 5),
      shell.execute("echo 2", 5),
      shell.execute("echo 3", 5),
    ]);

    expect(results[0].stdout.trim()).toBe("1");
    expect(results[1].stdout.trim()).toBe("2");
    expect(results[2].stdout.trim()).toBe("3");
    for (const r of results) expect(r.exitCode).toBe(0);
  }, 15_000);

  it("aborts a queued execute() without running its bash command", async () => {
    const shell = make();
    const ac = new AbortController();

    const first = shell.execute("sleep 1", 10);
    // Fire the second call synchronously so it queues, then abort before
    // its turn arrives.
    const queued = shell.execute("sleep 5", 10, undefined, ac.signal);
    ac.abort();

    const start = Date.now();
    const queuedResult = await queued;
    const elapsed = Date.now() - start;

    expect(queuedResult.exitCode).toBe(130);
    expect(queuedResult.stderr).toContain("aborted");
    // Must not have run its own 5s sleep — aborted calls bail on turn arrival.
    expect(elapsed).toBeLessThan(3_000);

    const firstResult = await first;
    expect(firstResult.exitCode).toBe(0);
  }, 15_000);

  it("stays responsive after a mixed workload of 30 commands", async () => {
    const shell = make();

    for (let i = 0; i < 10; i++) {
      const r = await shell.execute(`echo iter-${i}`, 5);
      expect(r.exitCode).toBe(0);
    }

    for (let i = 0; i < 2; i++) {
      await shell.execute("cat", 2);
    }

    await shell.execute("while :; do echo s-$RANDOM; done &", 3);

    await shell.execute("sleep 10 | cat", 2);

    const start = Date.now();
    const final = await shell.execute("echo final", 5);
    const elapsed = Date.now() - start;

    expect(final.exitCode).toBe(0);
    expect(final.stdout).toContain("final");
    expect(elapsed).toBeLessThan(3_000);
  }, 60_000);
});

describe("extractFallbackStdout", () => {
  const cut = "__APEX_deadbeef00112233__CUTOVER";
  const exitPrefix = "__APEX_deadbeef00112233__EXIT_";

  const mk = (stream: string, authoritative = "") => ({
    authoritativeStdout: authoritative,
    streamedStdout: stream,
    cutoverMarker: cut,
    exitMarkerPrefix: exitPrefix,
  });

  it("prefers authoritativeStdout over streamedStdout when populated", () => {
    expect(extractFallbackStdout(mk("ignored", "real output\n"))).toBe(
      "real output\n",
    );
  });

  it("strips exit marker from authoritativeStdout when fallback fires mid-phase", () => {
    const auth = "probe results\n" + exitPrefix + "0\n";
    expect(extractFallbackStdout(mk("ignored", auth))).toBe("probe results\n");
  });

  it("returns '(no output)' when authoritativeStdout contains only the exit marker", () => {
    expect(extractFallbackStdout(mk("ignored", exitPrefix + "137\n"))).toBe(
      "(no output)",
    );
  });

  it("strips both cutover prefix and exit-marker suffix from streamed buffer", () => {
    const leaked =
      cut +
      "\n" +
      "/console -> HTTP 404\n/debug -> HTTP 404\n" +
      exitPrefix +
      "0\n";
    expect(extractFallbackStdout(mk(leaked))).toBe(
      "/console -> HTTP 404\n/debug -> HTTP 404\n",
    );
  });

  it("strips cutover when exit marker was never emitted (killed mid-cat)", () => {
    const leaked = cut + "\n" + "[FOUND] /health -> HTTP 200\n";
    expect(extractFallbackStdout(mk(leaked))).toBe(
      "[FOUND] /health -> HTTP 200\n",
    );
  });

  it("strips exit marker when cutover was never emitted (tail never flushed)", () => {
    const leaked = exitPrefix + "143\n";
    expect(extractFallbackStdout(mk(leaked))).toBe("(no output)");
  });

  it("returns '(no output)' when both markers absent and buffer empty", () => {
    expect(extractFallbackStdout(mk(""))).toBe("(no output)");
  });

  it("returns raw buffer when neither marker present but bytes did stream", () => {
    expect(extractFallbackStdout(mk("partial probe output\n"))).toBe(
      "partial probe output\n",
    );
  });

  it("handles cutover immediately followed by exit marker (empty command output)", () => {
    const leaked = cut + "\n" + exitPrefix + "0\n";
    expect(extractFallbackStdout(mk(leaked))).toBe("(no output)");
  });
});
