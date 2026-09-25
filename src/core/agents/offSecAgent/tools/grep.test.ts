import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { winScriptFromEnv } from "./__tests__/sandboxScript";
import { type GrepResult, grep } from "./grep";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

vi.mock("node:child_process", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:child_process")>();
  return { ...original, spawn: vi.fn(original.spawn) };
});

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
    ...overrides,
  };
}

const scratchDirs: string[] = [];
function scratchDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "apex-grep-test-"));
  scratchDirs.push(dir);
  return dir;
}

type GrepCall = Parameters<NonNullable<ReturnType<typeof grep>["execute"]>>[0];

async function runGrep(ctx: ToolContext, input: GrepCall): Promise<GrepResult> {
  return (await grep(ctx).execute?.(input, {
    toolCallId: "tc_test",
    messages: [],
    abortSignal: ctx.abortSignal,
  })) as GrepResult;
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
  for (const dir of scratchDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function controlledChild() {
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    kill: vi.fn(() => true),
    exitCode: null as number | null,
    signalCode: null as NodeJS.Signals | null,
  });
  vi.mocked(spawn).mockImplementationOnce(
    () => child as unknown as ChildProcess,
  );
  return child;
}

describe("grep terminal ordering", () => {
  it.each([
    ["abort", 0],
    ["timeout", 0],
    ["abort", 1],
    ["timeout", 1],
  ] as const)("ignores late %s after exit %i while pipes drain", async (cause, code) => {
    vi.useFakeTimers();
    const child = controlledChild();
    const ac = new AbortController();
    const pending = runGrep(makeCtx({ abortSignal: ac.signal }), {
      pattern: "match",
      toolCallDescription: "completed search",
    });
    // Path resolution is async now; wait for the real spawn before emitting.
    await vi.waitFor(() => expect(spawn).toHaveBeenCalled());

    if (code === 0) child.stdout.emit("data", Buffer.from("first match\n"));
    child.exitCode = code;
    child.emit("exit", code, null);
    if (cause === "abort") ac.abort();
    else vi.advanceTimersByTime(30_000);
    if (code === 0) child.stdout.emit("data", Buffer.from("last match\n"));
    child.emit("close", code, null);

    const result = await pending;
    expect(child.kill).not.toHaveBeenCalled();
    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.truncated).toBeUndefined();
    expect(result.matchCount).toBe(code === 0 ? 2 : 0);
    expect(result.output).toBe(
      code === 0 ? "first match\nlast match\n" : "(no matches)",
    );
  });

  it.each([
    "abort",
    "timeout",
  ] as const)("keeps an earlier %s incomplete even if the child later exits zero", async (cause) => {
    vi.useFakeTimers();
    const child = controlledChild();
    const ac = new AbortController();
    const pending = runGrep(makeCtx({ abortSignal: ac.signal }), {
      pattern: "match",
      toolCallDescription: "interrupted search",
    });
    await vi.waitFor(() => expect(spawn).toHaveBeenCalled());

    child.stdout.emit("data", Buffer.from("partial match\n"));
    if (cause === "abort") ac.abort();
    else vi.advanceTimersByTime(30_000);
    if (cause === "abort") vi.advanceTimersByTime(30_000);
    else ac.abort();
    child.exitCode = 0;
    child.emit("exit", 0, null);
    child.emit("close", 0, null);

    const result = await pending;
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    expect(child.kill).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(false);
    expect(result.error).toContain(cause === "abort" ? "aborted" : "timed out");
    expect(result.truncated).toBe(true);
    expect(result.matchCount).toBeUndefined();
    expect(result.output).toBe("partial match\n");
  });
});

describe("grep healthy paths", () => {
  it("returns exact matches with an exact count", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "keep this line\nskip\nkeep also\n");
    writeFileSync(join(dir, "b.txt"), "nothing here\n");

    const result = await runGrep(makeCtx({ agentCwd: dir }), {
      pattern: "keep",
      directory: ".",
      toolCallDescription: "search for keep",
    });

    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.matchCount).toBe(2);
    expect(result.output).toContain("keep this line");
    expect(result.output).toContain("keep also");
    expect(result.truncated).toBeUndefined();
  });

  it("treats a genuine grep exit 1 with no stderr as no matches", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "nothing matching\n");

    const result = await runGrep(makeCtx({ agentCwd: dir }), {
      pattern: "absent-pattern",
      directory: ".",
      toolCallDescription: "no-match search",
    });

    expect(result.success).toBe(true);
    expect(result.output).toBe("(no matches)");
    expect(result.matchCount).toBe(0);
    expect(result.truncated).toBeUndefined();
  });
});

describe("grep bounded producer", () => {
  it("caps a massive result set at the producer and omits the match count", async () => {
    const dir = scratchDir();
    // ~10k matching lines ≈ 150k output chars — well past the 50k cap.
    writeFileSync(join(dir, "big.txt"), "needle-line\n".repeat(10_000));

    const result = await runGrep(makeCtx({ agentCwd: dir }), {
      pattern: "needle",
      directory: ".",
      toolCallDescription: "massive result set",
    });

    expect(result.success).toBe(false);
    expect(result.truncated).toBe(true);
    expect(result.error).toContain("capped");
    // An exact count is impossible from a capped window — never guessed.
    expect(result.matchCount).toBeUndefined();
    expect(result.output.length).toBeLessThanOrEqual(50_000 + 400);
    expect(result.output).toContain("truncated at");
    // Recursive grep prefixes each line with its filename (path-agnostic).
    expect(result.output).toContain("big.txt:needle-line");
  }, 10_000);
});

describe("grep interruption labeling", () => {
  it("an abort right after execute is partial evidence, never 'no matches'", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "target text\n");

    const ac = new AbortController();
    const ctx = makeCtx({ agentCwd: dir, abortSignal: ac.signal });
    const pending = grep(ctx).execute?.(
      {
        pattern: "target",
        directory: ".",
        toolCallDescription: "search that gets aborted",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    );
    ac.abort();
    const result = (await pending) as GrepResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("Grep aborted by user");
    // Interruption must not fabricate complete no-match evidence.
    expect(result.output).not.toBe("(no matches)");
    expect(result.matchCount).toBeUndefined();
    expect(result.truncated).toBe(true);
  }, 5_000);

  it("a nonzero error exit keeps partial output and omits the count", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "content\n");

    // Invalid regex → grep exits 2 with a stderr diagnostic.
    const result = await runGrep(makeCtx({ agentCwd: dir }), {
      pattern: "([unclosed",
      directory: ".",
      flags: "-E",
      toolCallDescription: "invalid pattern",
    });

    expect(result.success).toBe(false);
    expect(result.error).not.toBe("");
    expect(result.output).not.toBe("(no matches)");
    expect(result.matchCount).toBeUndefined();
    expect(result.truncated).toBeUndefined();
  });
});

describe("grep flag validation", () => {
  it.each([
    ["-f patterns.txt"],
    ["-Ff patterns.txt"],
    ["--file=patterns.txt"],
    ["--exclude-from=skip.txt"],
    ["extra-operand.txt"],
    // Alternate-pattern routes shift the caller's pattern into a file
    // operand position.
    ["-e"],
    ["-e ALT"],
    ["-ie"],
    ["--regexp=ALT"],
    ["--"],
    // Stray or malformed numeric tokens.
    ["3"],
    ["-rn 3"],
    ["-C"],
    ["-C x"],
    ["-A 2 2"],
    ["--include"],
    ["--include="],
    ["--color=always"],
    ["-X"],
  ])("rejects flag manipulation: %s", async (flags) => {
    const result = await runGrep(makeCtx(), {
      pattern: "x",
      flags,
      toolCallDescription: "flag manipulation attempt",
    });

    expect(result.success).toBe(false);
    expect(result.error).not.toBe("");
    expect(result.error).not.toContain("not found");
    expect(spawn).not.toHaveBeenCalled();
  });

  it.each([
    ["-rn -C 1"],
    ["-C3"],
    ["-rnC 2"],
    ['-i --include="*.ts"'],
    ["--ignore-case --line-number"],
    ["-rniE"],
  ])("accepts supported flag forms: %s", async (flags) => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.ts"), "one\nKEEP two\nthree\n");
    writeFileSync(join(dir, "b.md"), "KEEP nope\n");

    const result = await runGrep(makeCtx({ agentCwd: dir }), {
      pattern: "KEEP",
      directory: ".",
      flags,
      toolCallDescription: "supported flag form",
    });

    expect(result.success).toBe(true);
    expect(result.output).toContain("a.ts");
    if (flags.includes("*.ts")) {
      expect(result.output).not.toContain("b.md");
    }
  });

  it("a pattern naming an outside file is never read as a file operand (local)", async () => {
    const root = scratchDir();
    const outside = scratchDir();
    writeFileSync(join(outside, "secret.txt"), "file-pattern-leak-marker\n");
    writeFileSync(join(root, "real.txt"), "benign\n");
    const outsidePath = join(outside, "secret.txt");

    // With -e/-- the caller's pattern would slide into a file-operand slot
    // and grep would read the outside file; every route must either reject
    // the flags or search for the literal path text.
    for (const flags of [undefined, "-e", "--regexp=ALT", "--", "-rn -e"]) {
      const result = await runGrep(makeCtx({ agentCwd: root }), {
        pattern: outsidePath,
        directory: ".",
        ...(flags ? { flags } : {}),
        toolCallDescription: "pattern-as-path search",
      });
      expect(result.output).not.toContain("file-pattern-leak-marker");
      if (flags) {
        expect(result.success).toBe(false);
      }
    }
  });

  it("a pattern naming an outside file is never read as a file operand (sandbox)", async () => {
    const root = scratchDir();
    const outside = scratchDir();
    writeFileSync(join(outside, "secret.txt"), "file-pattern-leak-marker\n");
    writeFileSync(join(root, "real.txt"), "benign\n");
    const outsidePath = join(outside, "secret.txt");

    for (const flags of [undefined, "-e", "--"]) {
      const result = await runGrep(
        makeCtx({ agentCwd: root, sandbox: realLinuxSandbox() }),
        {
          pattern: outsidePath,
          directory: ".",
          ...(flags ? { flags } : {}),
          toolCallDescription: "sandbox pattern-as-path search",
        },
      );
      expect(result.output).not.toContain("file-pattern-leak-marker");
      if (flags) {
        expect(result.success).toBe(false);
      }
    }
  });
});

// The linux sandbox fake executes the real search scripts through bash,
// including the remote resolve round trip.
function realLinuxSandbox(): UnifiedSandbox {
  return {
    type: "linux",
    execute: async (command, opts) => {
      const res = spawnSync("bash", ["-c", command], {
        encoding: "utf8",
        timeout: 35_000,
        env: { ...process.env, ...opts?.envVars },
      });
      return {
        stdout: res.stdout ?? "",
        stderr: res.stderr ?? "",
        exitCode: res.status ?? 1,
        success: res.status === 0,
      };
    },
  };
}

describe("grep scope confinement", () => {
  it("rejects -R while a file workspace scope is active", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "content\n");

    const result = await runGrep(
      makeCtx({ agentCwd: dir, fileWorkspaceRoot: dir }),
      {
        pattern: "content",
        directory: ".",
        flags: "-Rn",
        toolCallDescription: "dereference attempt",
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain("-R");
    expect(spawn).not.toHaveBeenCalled();
  });

  it("-R stays available without a file workspace scope", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "content\n");

    const result = await runGrep(makeCtx({ agentCwd: dir }), {
      pattern: "content",
      directory: ".",
      flags: "-Rn",
      toolCallDescription: "unconstrained dereference search",
    });

    expect(result.success).toBe(true);
    expect(result.output).toContain("a.txt:1:content");
  });

  it("a scoped search cannot leak target-source bytes through a file symlink", async () => {
    const root = scratchDir();
    writeFileSync(join(root, "inside.txt"), "benign-content\n");
    const outside = scratchDir();
    writeFileSync(join(outside, "leaked-secret.txt"), "target-source-secret\n");
    symlinkSync(
      join(outside, "leaked-secret.txt"),
      join(root, "leak-link.txt"),
    );

    // Scoped to the workspace: the search fails before any grep runs.
    const scoped = await runGrep(
      makeCtx({ agentCwd: root, fileWorkspaceRoot: root }),
      {
        pattern: "target-source-secret",
        directory: ".",
        flags: "-R",
        toolCallDescription: "scoped dereference leak attempt",
      },
    );
    expect(scoped.success).toBe(false);

    // Unconstrained (no workspace root): resolveFilePath allows the symlinked
    // FILE operand itself, but -r never dereferences during recursion, so the
    // link is reported by name only — its target's bytes stay out of output.
    const unscoped = await runGrep(makeCtx({ agentCwd: root }), {
      pattern: "target-source-secret",
      directory: ".",
      toolCallDescription: "unscoped symlink search",
    });
    expect(unscoped.success).toBe(true);
    expect(unscoped.output).not.toContain("target-source-secret");
  });

  it("a scoped recursive search resolves a symlinked file operand explicitly requested", async () => {
    const root = scratchDir();
    writeFileSync(join(root, "real.txt"), "benign-content\n");
    const outside = scratchDir();
    writeFileSync(join(outside, "leaked.txt"), "target-source-secret\n");
    symlinkSync(join(outside, "leaked.txt"), join(root, "leak-link.txt"));

    const result = await runGrep(
      makeCtx({ agentCwd: root, fileWorkspaceRoot: root }),
      {
        pattern: "secret",
        directory: "leak-link.txt",
        toolCallDescription: "scoped symlinked file operand",
      },
    );

    // resolveFilePath canonicalizes the symlink and rejects it as escaping
    // the workspace before grep ever runs.
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes/i);
    expect(spawn).not.toHaveBeenCalled();
  });
});

// The linux sandbox fake executes the real search scripts through bash,
// including the remote resolve round trip.
describe("grep sandbox (linux, real execution)", () => {
  it("returns exact matches with an exact count, matching local output shape", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "keep this line\nskip\nkeep also\n");
    writeFileSync(join(dir, "b.txt"), "nothing here\n");

    const ctx = makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() });
    const result = await runGrep(ctx, {
      pattern: "keep",
      directory: ".",
      toolCallDescription: "sandbox search",
    });

    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.matchCount).toBe(2);
    expect(result.output).toContain("keep this line");
    expect(result.output).toContain("keep also");
    expect(result.truncated).toBeUndefined();
  });

  it("treats a genuine no-match as (no matches) with count 0", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "nothing matching\n");

    const result = await runGrep(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        pattern: "absent-pattern",
        directory: ".",
        toolCallDescription: "sandbox no-match search",
      },
    );

    expect(result.success).toBe(true);
    expect(result.output).toBe("(no matches)");
    expect(result.matchCount).toBe(0);
  });

  it("caps massive output at the producer and reports truncation", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "big.txt"), "needle-line\n".repeat(10_000));

    const result = await runGrep(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        pattern: "needle",
        directory: ".",
        toolCallDescription: "sandbox massive result set",
      },
    );

    expect(result.success).toBe(false);
    expect(result.truncated).toBe(true);
    expect(result.error).toContain("capped");
    expect(result.matchCount).toBeUndefined();
    expect(result.output).toContain("truncated at");
  }, 15_000);

  it("never dereferences symlinks during sandbox recursion", async () => {
    const root = scratchDir();
    writeFileSync(join(root, "real.txt"), "benign-content\n");
    const outside = scratchDir();
    writeFileSync(join(outside, "leaked.txt"), "target-source-secret\n");
    symlinkSync(join(outside, "leaked.txt"), join(root, "leak-link.txt"));

    const result = await runGrep(
      makeCtx({ agentCwd: root, sandbox: realLinuxSandbox() }),
      {
        pattern: "target-source-secret",
        directory: ".",
        toolCallDescription: "sandbox symlink leak attempt",
      },
    );

    expect(result.success).toBe(true);
    expect(result.output).toBe("(no matches)");
    expect(result.matchCount).toBe(0);
  });

  it("surfaces an invalid pattern as an explicit failure", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "content\n");

    const result = await runGrep(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        pattern: "([unclosed",
        directory: ".",
        flags: "-E",
        toolCallDescription: "sandbox invalid pattern",
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).not.toBe("");
    expect(result.matchCount).toBeUndefined();
  });
});

// No local PowerShell on this host: pin the windows transport shape — static
// command, env-only data, marker protocol, unsupported-flag rejection.
describe("grep sandbox transport shape (windows)", () => {
  // The fake replays script behavior: stdout carries matches plus the exit
  // marker, and the process exit mirrors what the script would set (exit 3
  // on cap, 0 otherwise).
  function windowsSandbox(
    onRead: (envVars: Record<string, string>) => string,
  ): {
    sandbox: UnifiedSandbox;
    calls: { command: string; envVars?: Record<string, string> }[];
  } {
    const calls: { command: string; envVars?: Record<string, string> }[] = [];
    return {
      calls,
      sandbox: {
        type: "windows",
        execute: async (command, opts) => {
          calls.push({ command, envVars: opts?.envVars });
          if (opts?.envVars?.APEX_FILE_SCRIPT !== undefined) {
            return {
              stdout: JSON.stringify({ ok: true, path: "C:\\w" }),
              stderr: "",
              exitCode: 0,
              success: true,
            };
          }
          const stdout = onRead(opts?.envVars ?? {});
          const exitCode = stdout.includes("GREP_EXIT_MARK_3") ? 3 : 0;
          return {
            stdout: stdout.replace("GREP_EXIT_MARK_3\n", ""),
            stderr: "",
            exitCode,
            success: true,
          };
        },
      },
    };
  }

  it("uses the static command with env-only data and parses the exit marker", async () => {
    const markerFor = (env: Record<string, string>) =>
      `${env.APEX_GREP_MARKER}0`;
    const { sandbox, calls } = windowsSandbox((env) => {
      const out = `C:\\w\\a.txt:1:keep this line\nC:\\w\\a.txt:3:keep also\n`;
      return `${out}\n${markerFor(env)}\n`;
    });

    const result = await runGrep(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "keep",
      directory: ".",
      toolCallDescription: "windows search",
    });

    const searchCall = calls[calls.length - 1];
    const command = searchCall.command;
    expect(command).toMatch(
      /^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/,
    );
    // The bootstrap is fixed and short — far under cmd.exe's 8191 limit.
    expect(command.length).toBeLessThan(1000);
    expect(searchCall.command).not.toContain("C:\\w");
    expect(searchCall.envVars?.APEX_GREP_PATH).toBe("C:\\w");
    expect(searchCall.envVars?.APEX_GREP_PATTERN).toBe("keep");
    expect(searchCall.envVars?.APEX_WIN_SCRIPT_COUNT).toBeDefined();
    const script = winScriptFromEnv(searchCall.envVars);
    expect(script).toContain("[Console]::OutputEncoding");
    expect(script).not.toContain("C:\\w");

    expect(result.success).toBe(true);
    expect(result.matchCount).toBe(2);
    expect(result.output).toContain("keep this line");
  });

  it("parses the no-match exit code as (no matches)", async () => {
    const { sandbox } = windowsSandbox((env) => `\n${env.APEX_GREP_MARKER}1\n`);

    const result = await runGrep(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "absent",
      directory: ".",
      toolCallDescription: "windows no-match search",
    });

    expect(result.success).toBe(true);
    expect(result.output).toBe("(no matches)");
    expect(result.matchCount).toBe(0);
  });

  it("treats exit 3 as a capped, truncated search", async () => {
    const { sandbox } = windowsSandbox(() => {
      // A capped script exits 3 without emitting its marker (the cap check
      // precedes the marker write), so the fake replays exactly that.
      const lines = `C:\\w\\big.txt:${"needle\n".repeat(100)}`;
      return `${lines}\nGREP_EXIT_MARK_3\n`;
    });

    const result = await runGrep(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "needle",
      directory: ".",
      toolCallDescription: "windows capped search",
    });

    expect(result.success).toBe(false);
    expect(result.truncated).toBe(true);
    expect(result.matchCount).toBeUndefined();
  });

  it("fails explicitly when the exit marker is missing", async () => {
    const { sandbox } = windowsSandbox(() => "orphan output");

    const result = await runGrep(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "x",
      directory: ".",
      toolCallDescription: "windows markerless search",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("sandbox grep failed");
  });

  it("rejects flags the windows script does not support, before executing", async () => {
    const { sandbox, calls } = windowsSandbox(() => "");

    const result = await runGrep(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "x",
      directory: ".",
      flags: "-C 2",
      toolCallDescription: "unsupported windows flag",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("windows sandbox search supports only");
    // Only the resolve round trip ran — no search script was shipped.
    expect(calls.filter((c) => c.envVars?.APEX_WIN_SCRIPT_COUNT)).toHaveLength(
      0,
    );
  });

  it("maps -i onto the script opts for the windows search", async () => {
    const { sandbox, calls } = windowsSandbox(
      (env) => `\n${env.APEX_GREP_MARKER}0\n`,
    );

    await runGrep(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "X",
      directory: ".",
      flags: "-rni",
      toolCallDescription: "windows case-insensitive search",
    });

    const searchCall = calls[calls.length - 1];
    expect(searchCall.envVars?.APEX_GREP_OPTS).toBe("r,n,i");
  });
});

// Real cmd.exe execution on Windows hosts: the transport, script-scope match
// state, streaming cap, and reparse-point skipping run exactly as shipped.
// Skipped elsewhere (no PowerShell on this host).
describe.skipIf(process.platform !== "win32")(
  "grep sandbox (windows process adapter, real execution)",
  () => {
    const windowsProcessSandbox: UnifiedSandbox = {
      type: "windows",
      async execute(command, options) {
        const res = spawnSync("cmd.exe", ["/d", "/s", "/c", command], {
          encoding: "utf8",
          env: { ...process.env, ...options?.envVars },
          timeout: (options?.timeout ?? 30) * 1000,
          maxBuffer: 3 * 1024 * 1024,
        });
        return {
          stdout: res.stdout ?? "",
          stderr: res.stderr ?? "",
          exitCode: res.status ?? 1,
          success: res.status === 0,
        };
      },
    };

    it("returns line-numbered matches with an exact count", async () => {
      const dir = scratchDir();
      writeFileSync(join(dir, "a.txt"), "keep this line\nskip\nkeep also\n");
      writeFileSync(join(dir, "b.txt"), "nothing here\n");

      const result = await runGrep(
        makeCtx({ agentCwd: dir, sandbox: windowsProcessSandbox }),
        {
          pattern: "keep",
          directory: ".",
          flags: "-n",
          toolCallDescription: "real windows search",
        },
      );

      expect(result.success).toBe(true);
      expect(result.matchCount).toBe(2);
      expect(result.output).toContain("a.txt:1:keep this line");
      expect(result.output).toContain("a.txt:3:keep also");
    });

    it("reports no matches with count 0", async () => {
      const dir = scratchDir();
      writeFileSync(join(dir, "a.txt"), "nothing\n");

      const result = await runGrep(
        makeCtx({ agentCwd: dir, sandbox: windowsProcessSandbox }),
        {
          pattern: "absent",
          directory: ".",
          toolCallDescription: "real windows no-match search",
        },
      );

      expect(result.success).toBe(true);
      expect(result.output).toBe("(no matches)");
      expect(result.matchCount).toBe(0);
    });

    it("skips a junction directory — no outside content is searched", async () => {
      const root = scratchDir();
      const outside = scratchDir();
      writeFileSync(join(outside, "leak.txt"), "junction-marker-content\n");
      writeFileSync(join(root, "real.txt"), "benign-content\n");
      symlinkSync(outside, join(root, "leak-dir"), "junction");

      const result = await runGrep(
        makeCtx({ agentCwd: root, sandbox: windowsProcessSandbox }),
        {
          pattern: "junction-marker-content",
          directory: ".",
          toolCallDescription: "real windows junction leak attempt",
        },
      );

      expect(result.success).toBe(true);
      expect(result.output).toBe("(no matches)");
      expect(result.matchCount).toBe(0);
    });

    it("skips a symlinked file — no outside content is searched", async () => {
      const root = scratchDir();
      const outside = scratchDir();
      writeFileSync(join(outside, "leak.txt"), "file-symlink-marker-content\n");
      let linked = true;
      try {
        symlinkSync(join(outside, "leak.txt"), join(root, "leak-link.txt"));
      } catch {
        linked = false; // Creating file symlinks can require dev mode.
      }

      if (!linked) return;
      const result = await runGrep(
        makeCtx({ agentCwd: root, sandbox: windowsProcessSandbox }),
        {
          pattern: "file-symlink-marker-content",
          directory: ".",
          toolCallDescription: "real windows file-symlink leak attempt",
        },
      );

      expect(result.success).toBe(true);
      expect(result.output).toBe("(no matches)");
      expect(result.matchCount).toBe(0);
    });

    it("caps a massive result set through the streaming pipeline", async () => {
      const dir = scratchDir();
      writeFileSync(join(dir, "big.txt"), "needle-line\n".repeat(10_000));

      const result = await runGrep(
        makeCtx({ agentCwd: dir, sandbox: windowsProcessSandbox }),
        {
          pattern: "needle",
          directory: ".",
          toolCallDescription: "real windows capped search",
        },
      );

      expect(result.success).toBe(false);
      expect(result.truncated).toBe(true);
      expect(result.error).toContain("capped");
      expect(result.matchCount).toBeUndefined();
      expect(result.output).toContain("truncated at");
    }, 30_000);
  },
);
