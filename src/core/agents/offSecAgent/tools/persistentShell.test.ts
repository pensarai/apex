import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { afterAll, afterEach, describe, expect, it } from "vitest";

import {
  extractFallbackStdout,
  getApexTmpRoot,
  PersistentShell,
  readSandboxAgentEnv,
} from "./persistentShell";

function tempfileCount(): number {
  const root = getApexTmpRoot();
  return existsSync(root) ? readdirSync(root).length : 0;
}

const HAS_STDBUF =
  process.platform !== "win32" &&
  spawnSync("stdbuf", ["--version"], { stdio: "ignore" }).status === 0;

describe("PersistentShell — long-running stability", () => {
  const shells: PersistentShell[] = [];
  const make = () => {
    const shell = new PersistentShell();
    shells.push(shell);
    return shell;
  };

  // Process-group cleanup can race sibling shells, so wait for concurrent cases.
  afterAll(() => {
    for (const shell of shells) shell.dispose();
  });

  it.concurrent("basic smoke: sequential commands return quickly", async () => {
    const shell = make();
    const r1 = await shell.execute("echo one", 5);
    expect(r1.exitCode).toBe(0);
    expect(r1.stdout).toContain("one");

    const r2 = await shell.execute("echo two", 5);
    expect(r2.exitCode).toBe(0);
    expect(r2.stdout).toContain("two");
  });

  it.concurrent("captures short stdout (no-stdbuf safe)", async () => {
    const shell = make();
    const r = await shell.execute("printf 'hello\\nworld\\n'", 5);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("hello");
    expect(r.stdout).toContain("world");
  });

  it.concurrent("captures trivial stdout even when tail block-buffers", async () => {
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

  it.concurrent("captures output across the 8 KiB block-buffer boundary", async () => {
    const shell = make();
    // 9000 > 8192 to exceed tail's default block-buffer.
    const r = await shell.execute(
      "head -c 9000 /dev/zero | tr '\\0' 'x'; echo",
      5,
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout.replace(/\n$/, "").length).toBe(9000);
  });

  it.concurrent("stays responsive after a command that normally reads stdin", async () => {
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

  it.concurrent("cleans up pipeline grandchildren when a command times out", async () => {
    const shell = make();
    await shell.execute("echo prime", 5);
    const bashPid = (shell as unknown as { proc: { pid: number } }).proc.pid;
    expect(bashPid).toBeGreaterThan(0);

    // Pipeline: sleep is a grandchild of bash (child of the subshell).
    const timed = await shell.execute("sleep 30 | cat", 2);
    expect(timed.exitCode).toBe(124);

    await new Promise((r) => setTimeout(r, 1_500));

    const { spawnSync } = await import("node:child_process");
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

  it.concurrent("does not leak background-process output into the next command's stdout", async () => {
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

  it.concurrent("persists cd and export across commands (documented contract)", async () => {
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

  it.concurrent("reports exit code 124 on timeout and kills descendants", async () => {
    const shell = make();
    const r = await shell.execute("sleep 30", 1);
    expect(r.exitCode).toBe(124);

    const after = await shell.execute("echo ok", 5);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("ok");
  }, 10_000);

  it.concurrent("does not leak nonce markers on timeout", async () => {
    const shell = make();
    const r = await shell.execute(`printf 'hello\\n'; sleep 10`, 1);
    expect(r.exitCode).toBe(124);
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
  }, 10_000);

  it.concurrent("does not leak nonce markers on abort", async () => {
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

  /**
   * Issue #644 — Partial output preservation on timeout.
   *
   * Long fuzzers (gobuster, ffuf) routinely outrun the per-command timeout
   * but the bytes they printed before the kill are already on disk in the
   * per-command tempfile. The 200ms grace + disk-read salvage surfaces
   * those bytes; before this fix, the SIGKILL escalation re-enumerated
   * bash's children and killed `cat` mid-flush, dropping partial output
   * to `(no output)`.
   */
  it.concurrent("preserves partial stdout when a command is killed by timeout", async () => {
    const shell = make();
    const r = await shell.execute(
      `printf 'hit-1\\n'; printf 'hit-2\\n'; sleep 30`,
      1,
    );
    expect(r.exitCode).toBe(124);
    expect(r.stdout).toContain("hit-1");
    expect(r.stdout).toContain("hit-2");
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);

    // Shell stays responsive after a salvaged timeout.
    const after = await shell.execute("echo ok", 5);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("ok");
  }, 15_000);

  it.concurrent("preserves partial stdout when a command is aborted", async () => {
    const shell = make();
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 200);
    const r = await shell.execute(
      `printf 'hit-a\\n'; printf 'hit-b\\n'; sleep 30`,
      30,
      undefined,
      ac.signal,
    );
    expect(r.exitCode).toBe(130);
    expect(r.stdout).toContain("hit-a");
    expect(r.stdout).toContain("hit-b");
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+___(CUTOVER|EXIT_)/);
  }, 15_000);

  /**
   * Salvage works even when the user command ignores SIGTERM. We read
   * the tempfile after a 200ms grace and BEFORE escalating to SIGKILL,
   * so anything the tool had already written reaches the agent — and
   * SIGKILL reliably ends it afterward.
   */
  it.concurrent("salvages stdout from a SIGTERM-resistant command", async () => {
    const shell = make();
    const r = await shell.execute(
      `bash -c "trap '' TERM; printf hit-trapped; sleep 30"`,
      1,
    );
    expect(r.exitCode).toBe(124);
    expect(r.stdout).toContain("hit-trapped");
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+__/);
  }, 10_000);

  /**
   * Salvage works for output that exceeds the kernel pipe buffer (~64 KB).
   * The pre-fix in-pipe approach would block `cat` once the pipe filled and
   * SIGKILL would truncate. Disk reads are unaffected by pipe state.
   */
  it.concurrent("salvages large partial output (>64 KB) on timeout", async () => {
    const shell = make();
    const r = await shell.execute(
      `for i in $(seq 1 4000); do printf 'line-%05d\\n' $i; done; sleep 30`,
      1,
    );
    expect(r.exitCode).toBe(124);
    expect(r.stdout).toContain("line-00001");
    expect(r.stdout).toContain("line-04000");
    expect(r.stdout).not.toMatch(/__APEX_[0-9a-f]+__/);
  }, 15_000);

  it.concurrent("returns (no output) when an empty-output command times out", async () => {
    const shell = make();
    const r = await shell.execute("sleep 30", 1);
    expect(r.exitCode).toBe(124);
    expect(r.stdout).toBe("(no output)");
  }, 10_000);

  /**
   * Issue #644 — Tempfile lifecycle. Node owns the per-command tempfiles
   * (the wrapper no longer `rm`s them). Every code path — happy completion,
   * timeout, abort, cancel, shell-died, dispose — must unlink the pair.
   */
  it("cleans up tempfiles after happy-path completion", async () => {
    const shell = make();
    const before = tempfileCount();
    await shell.execute("echo done", 5);
    await new Promise((r) => setTimeout(r, 50));
    expect(tempfileCount()).toBe(before);
  });

  it("cleans up tempfiles after a timeout", async () => {
    const shell = make();
    const before = tempfileCount();
    const r = await shell.execute("printf 'partial\\n'; sleep 30", 1);
    expect(r.exitCode).toBe(124);
    expect(r.stdout).toContain("partial");
    await new Promise((r) => setTimeout(r, 50));
    expect(tempfileCount()).toBe(before);
  }, 10_000);

  it("cleans up tempfiles after an abort", async () => {
    const shell = make();
    const before = tempfileCount();
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const r = await shell.execute(
      "printf 'partial\\n'; sleep 30",
      30,
      undefined,
      ac.signal,
    );
    expect(r.exitCode).toBe(130);
    expect(r.stdout).toContain("partial");
    await new Promise((r) => setTimeout(r, 50));
    expect(tempfileCount()).toBe(before);
  }, 10_000);

  it("does not leak tempfiles across many sequential commands", async () => {
    const shell = make();
    const before = tempfileCount();
    for (let i = 0; i < 20; i++) {
      await shell.execute(`echo iter-${i}`, 5);
    }
    await new Promise((r) => setTimeout(r, 50));
    expect(tempfileCount()).toBe(before);
  }, 30_000);

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

  it.concurrent("does not cross-contaminate stdout across parallel execute() calls", async () => {
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

  it.concurrent("does not cross-contaminate stderr across parallel execute() calls", async () => {
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

  it.concurrent("isolates parallel-call timeouts (no marker or kill-message leakage)", async () => {
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

  it.concurrent("preserves FIFO ordering for parallel execute() calls", async () => {
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

  it("includes queue wait in each command timeout", async () => {
    const shell = make();
    const first = shell.execute("sleep 1", 5);

    const startedAt = Date.now();
    const queued = await shell.execute("echo should-not-run", 0.2);

    expect(queued.exitCode).toBe(124);
    expect(queued.stderr).toContain("waiting for the persistent shell");
    expect(queued.stdout).not.toContain("should-not-run");
    expect(Date.now() - startedAt).toBeLessThan(800);

    expect((await first).exitCode).toBe(0);
    const recovered = await shell.execute("echo recovered", 5);
    expect(recovered.exitCode).toBe(0);
    expect(recovered.stdout).toContain("recovered");
  }, 10_000);

  it.concurrent("aborts a queued execute() without running its bash command", async () => {
    const shell = make();
    const ac = new AbortController();

    const first = shell.execute("sleep 2", 10);
    // Fire the second call synchronously so it queues, then abort before
    // its turn arrives.
    const queued = shell.execute("sleep 5", 10, undefined, ac.signal);
    ac.abort();

    const start = Date.now();
    const queuedResult = await queued;
    const elapsed = Date.now() - start;

    expect(queuedResult.exitCode).toBe(130);
    expect(queuedResult.stderr).toContain("aborted");
    // Must not wait for the active command or run its own 5s sleep.
    expect(elapsed).toBeLessThan(1_000);

    const firstResult = await first;
    expect(firstResult.exitCode).toBe(0);
  }, 15_000);

  it.concurrent("stays responsive after a mixed workload of 30 commands", async () => {
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

    await shell.execute(
      "kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; true",
      3,
    );

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
    const auth = `probe results\n${exitPrefix}0\n`;
    expect(extractFallbackStdout(mk("ignored", auth))).toBe("probe results\n");
  });

  it("returns '(no output)' when authoritativeStdout contains only the exit marker", () => {
    expect(extractFallbackStdout(mk("ignored", `${exitPrefix}137\n`))).toBe(
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
    const leaked = `${cut}\n[FOUND] /health -> HTTP 200\n`;
    expect(extractFallbackStdout(mk(leaked))).toBe(
      "[FOUND] /health -> HTTP 200\n",
    );
  });

  it("strips exit marker when cutover was never emitted (tail never flushed)", () => {
    const leaked = `${exitPrefix}143\n`;
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
    const leaked = `${cut}\n${exitPrefix}0\n`;
    expect(extractFallbackStdout(mk(leaked))).toBe("(no output)");
  });
});

describe("readSandboxAgentEnv", () => {
  const orig = process.env.PENSAR_AGENT_ENV_VARS;
  afterEach(() => {
    if (orig === undefined) delete process.env.PENSAR_AGENT_ENV_VARS;
    else process.env.PENSAR_AGENT_ENV_VARS = orig;
  });

  it("parses a JSON object of string values", () => {
    process.env.PENSAR_AGENT_ENV_VARS = JSON.stringify({
      API_TOKEN: "tok",
      BASE_URL: "https://x",
    });
    expect(readSandboxAgentEnv()).toEqual({
      API_TOKEN: "tok",
      BASE_URL: "https://x",
    });
  });

  it("returns {} when unset", () => {
    delete process.env.PENSAR_AGENT_ENV_VARS;
    expect(readSandboxAgentEnv()).toEqual({});
  });

  it("fails soft to {} on malformed JSON", () => {
    process.env.PENSAR_AGENT_ENV_VARS = "{not json";
    expect(readSandboxAgentEnv()).toEqual({});
  });

  it("ignores non-string values and non-object blobs", () => {
    process.env.PENSAR_AGENT_ENV_VARS = JSON.stringify({
      KEEP: "yes",
      DROP: 123,
    });
    expect(readSandboxAgentEnv()).toEqual({ KEEP: "yes" });

    process.env.PENSAR_AGENT_ENV_VARS = JSON.stringify(["a", "b"]);
    expect(readSandboxAgentEnv()).toEqual({});
  });
});

describe("PersistentShell — sandbox agent env injection", () => {
  const shells: PersistentShell[] = [];
  const orig = process.env.PENSAR_AGENT_ENV_VARS;

  afterEach(() => {
    while (shells.length) {
      try {
        shells.pop()?.dispose();
      } catch {
        // ignore
      }
    }
    if (orig === undefined) delete process.env.PENSAR_AGENT_ENV_VARS;
    else process.env.PENSAR_AGENT_ENV_VARS = orig;
  });

  it("exposes PENSAR_AGENT_ENV_VARS to execute_command", async () => {
    process.env.PENSAR_AGENT_ENV_VARS = JSON.stringify({
      MY_AGENT_TOKEN: "s3cr3t-value",
    });
    const shell = new PersistentShell();
    shells.push(shell);

    const r = await shell.execute('echo "tok=$MY_AGENT_TOKEN"', 5);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("tok=s3cr3t-value");
  });

  it("lets explicit per-agent env override the sandbox blob", async () => {
    process.env.PENSAR_AGENT_ENV_VARS = JSON.stringify({
      SHARED: "from-blob",
    });
    const shell = new PersistentShell({ env: { SHARED: "from-extra-env" } });
    shells.push(shell);

    const r = await shell.execute('echo "v=$SHARED"', 5);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("v=from-extra-env");
  });

  it("does not leak unrelated process.env into the shell", async () => {
    delete process.env.PENSAR_AGENT_ENV_VARS;
    process.env.__APEX_TEST_LEAK_CHECK = "should-not-appear";
    const shell = new PersistentShell();
    shells.push(shell);

    const r = await shell.execute('echo "leak=[$__APEX_TEST_LEAK_CHECK]"', 5);
    delete process.env.__APEX_TEST_LEAK_CHECK;
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("leak=[]");
  });
});
