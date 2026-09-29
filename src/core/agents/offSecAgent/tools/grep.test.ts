import { type ChildProcess, spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { type GrepResult, grep } from "./grep";
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
