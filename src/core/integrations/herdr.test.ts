import { type ChildProcess, spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHerdrReporter, type HerdrReport } from "./herdr";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

const env = {
  HERDR_ENV: "1",
  HERDR_PANE_ID: "w1:p1",
  HERDR_BIN_PATH: "/fixture/Herdr App/herdr",
  HERDR_SOCKET_PATH: "/fixture/herdr.sock",
};
const session = {
  id: "ses_fixture",
  resumeArgv: ["pensar", "--resume", "ses_fixture", "--model", "model/name"],
};
const spawnMock = vi.mocked(spawn);
const children: Array<
  EventEmitter & {
    kill: ReturnType<typeof vi.fn>;
    unref: ReturnType<typeof vi.fn>;
  }
> = [];

function argv(index: number): string[] {
  return spawnMock.mock.calls[index][1] as string[];
}

function option(index: number, flag: string): string | undefined {
  const args = argv(index);
  const position = args.indexOf(flag);
  return position === -1 ? undefined : args[position + 1];
}

async function complete(index: number, code = 0): Promise<void> {
  children[index].emit("spawn");
  children[index].emit("close", code);
  await vi.advanceTimersByTimeAsync(0);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-06T12:00:00Z"));
  children.length = 0;
  spawnMock.mockReset();
  spawnMock.mockImplementation(() => {
    const child = Object.assign(new EventEmitter(), {
      kill: vi.fn(() => true),
      unref: vi.fn(),
    });
    children.push(child);
    return child as unknown as ChildProcess;
  });
});

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

describe("Herdr reporting", () => {
  it.each(Object.keys(env))("does nothing without %s", async (key) => {
    const incomplete: NodeJS.ProcessEnv = { ...env };
    delete incomplete[key];
    const reporter = createHerdrReporter(incomplete);
    reporter.report({ state: "working", session });
    await reporter.release();
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("requires the exact managed-environment marker", async () => {
    const reporter = createHerdrReporter({ ...env, HERDR_ENV: "true" });
    reporter.report({ state: "idle" });
    await reporter.release();
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("uses the inherited binary and socket without a shell or terminal output", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({
      state: "blocked",
      message: "Waiting for approval",
      session,
    });
    expect(spawnMock).toHaveBeenCalledWith(
      env.HERDR_BIN_PATH,
      expect.any(Array),
      { env, stdio: "ignore", windowsHide: true },
    );
    expect(argv(0).slice(0, 3)).toEqual(["pane", "report-agent", "w1:p1"]);
    expect(option(0, "--source")).toBe("pensar-apex");
    expect(option(0, "--agent")).toBe("apex");
    expect(option(0, "--state")).toBe("blocked");
    expect(option(0, "--message")).toBe("Waiting for approval");
    expect(option(0, "--agent-session-id")).toBe(session.id);
    expect(argv(0).slice(argv(0).indexOf("--") + 1)).toEqual(
      session.resumeArgv,
    );
    expect(Number.isSafeInteger(Number(option(0, "--seq")))).toBe(true);
    await complete(0);
  });

  it("can replace the resume command with the home screen", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "idle", session: { resumeArgv: ["pensar"] } });
    expect(option(0, "--agent-session-id")).toBeUndefined();
    expect(argv(0).slice(-2)).toEqual(["--", "pensar"]);
    await complete(0);
  });

  it.each([
    [],
    ["/usr/bin/pensar"],
    ["C:\\tools\\pensar.exe"],
    ["pensar+extra"],
    ["pensar", "model'quoted"],
    ["pensar", "line\nbreak"],
    ["pensar", "control\u0085"],
    ["pensar", ...Array<string>(64).fill("arg")],
    ["pensar", "a".repeat(8_192)],
    ["pensar", "🧪".repeat(2_050)],
  ])("keeps reporting state when resume argv is invalid: %j", async (...resumeArgv) => {
    const reporter = createHerdrReporter(env);
    reporter.report({
      state: "working",
      session: { id: session.id, resumeArgv },
    });
    expect(option(0, "--state")).toBe("working");
    expect(argv(0)).not.toContain("--");
    await complete(0);
  });

  it("counts the 8 KiB limit as UTF-8 argument bytes", async () => {
    const reporter = createHerdrReporter(env);
    const resumeArgv = [
      "pensar",
      "a".repeat(8_192 - Buffer.byteLength("pensar")),
    ];
    reporter.report({ state: "idle", session: { resumeArgv } });
    expect(argv(0).slice(argv(0).indexOf("--") + 1)).toEqual(resumeArgv);
    await complete(0);

    reporter.report({
      state: "working",
      session: { resumeArgv: [...resumeArgv, "a"] },
    });
    expect(option(1, "--state")).toBe("working");
    expect(argv(1)).not.toContain("--");
    await complete(1);
  });

  it("omits invalid session metadata without losing state", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({
      state: "idle",
      session: { id: "bad\0id", resumeArgv: [] },
    });
    expect(option(0, "--state")).toBe("idle");
    expect(option(0, "--agent-session-id")).toBeUndefined();
    await complete(0);
  });

  it("coalesces queued transitions and session switches to the latest snapshot", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working", session });
    reporter.report({ state: "idle", session });
    const next: HerdrReport = {
      state: "blocked",
      message: "Answer questions",
      session: {
        id: "ses_next",
        resumeArgv: ["pensar", "--resume", "ses_next"],
      },
    };
    reporter.report(next);
    next.session?.resumeArgv.push("--changed-after-report");
    expect(spawnMock).toHaveBeenCalledTimes(1);
    await complete(0);
    expect(spawnMock).toHaveBeenCalledTimes(2);
    expect(option(1, "--state")).toBe("blocked");
    expect(option(1, "--agent-session-id")).toBe("ses_next");
    expect(argv(1)).not.toContain("--changed-after-report");
    await complete(1);
  });

  it("deduplicates successful snapshots but retries a failed one", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working", session });
    await complete(0, 1);
    reporter.report({ state: "working", session });
    expect(spawnMock).toHaveBeenCalledTimes(2);
    await complete(1);
    reporter.report({ state: "working", session });
    await vi.advanceTimersByTimeAsync(0);
    expect(spawnMock).toHaveBeenCalledTimes(2);
    reporter.report({
      state: "working",
      session: { ...session, id: "ses_next" },
    });
    expect(spawnMock).toHaveBeenCalledTimes(3);
    await complete(2);
  });

  it("falls back once for older CLIs and preserves native session identity", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working", session });
    await complete(0, 2);
    expect(spawnMock).toHaveBeenCalledTimes(2);
    expect(argv(1)).not.toContain("--");
    expect(option(1, "--agent-session-id")).toBe(session.id);
    expect(Number(option(1, "--seq"))).toBeGreaterThan(
      Number(option(0, "--seq")),
    );
    await complete(1);
    reporter.report({ state: "idle", session });
    expect(argv(2)).not.toContain("--");
    await complete(2);
  });

  it("deduplicates sessions regardless of property order", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "idle", session });
    await complete(0);
    reporter.report({
      state: "idle",
      session: { resumeArgv: [...session.resumeArgv], id: session.id },
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(spawnMock).toHaveBeenCalledTimes(1);
  });

  it("uses the latest queued state instead of retrying a stale compatibility report", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working", session });
    reporter.report({ state: "blocked", session });
    await complete(0, 2);
    expect(spawnMock).toHaveBeenCalledTimes(2);
    expect(option(1, "--state")).toBe("blocked");
    expect(argv(1)).not.toContain("--");
    await complete(1);
  });

  it("does not retry server errors or syntax errors without resume arguments", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working", session });
    await complete(0, 1);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    reporter.report({ state: "idle" });
    await complete(1, 2);
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it("ignores spawn failures and accepts later reports", async () => {
    const reporter = createHerdrReporter(env);
    spawnMock.mockImplementationOnce(() => {
      throw new Error("ENOENT");
    });
    expect(() => reporter.report({ state: "working" })).not.toThrow();
    await vi.advanceTimersByTimeAsync(0);
    reporter.report({ state: "idle" });
    children[0].emit("error", new Error("EACCES"));
    await vi.advanceTimersByTimeAsync(0);
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it("releases exactly once after the in-flight report, dropping queued work", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working", session });
    reporter.report({ state: "blocked", session });
    const release = reporter.release();
    expect(reporter.release()).toBe(release);
    reporter.report({ state: "idle", session });
    expect(spawnMock).toHaveBeenCalledTimes(1);
    await complete(0);
    expect(argv(1).slice(0, 3)).toEqual(["pane", "release-agent", "w1:p1"]);
    expect(Number(option(1, "--seq"))).toBeGreaterThan(
      Number(option(0, "--seq")),
    );
    await complete(1);
    await release;
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it("bounds both a stuck report and release even when the child never closes", async () => {
    const reporter = createHerdrReporter(env);
    reporter.report({ state: "working" });
    children[0].emit("spawn");
    const release = reporter.release();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(children[0].kill).toHaveBeenCalledWith("SIGKILL");
    expect(argv(1)[1]).toBe("release-agent");
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(release).resolves.toBeUndefined();
    expect(children[1].kill).toHaveBeenCalledWith("SIGKILL");
    expect(children[1].unref).toHaveBeenCalled();
    children[0].emit("close", 0);
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it("does not release when no report process could start", async () => {
    const first = createHerdrReporter(env);
    spawnMock.mockImplementationOnce(() => {
      throw new Error("ENOENT");
    });
    first.report({ state: "working" });
    await first.release();
    expect(spawnMock).toHaveBeenCalledTimes(1);

    const second = createHerdrReporter(env);
    second.report({ state: "working" });
    children[0].emit("error", new Error("EACCES"));
    await second.release();
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it("does not release a pane that this instance never reported", async () => {
    const reporter = createHerdrReporter(env);
    await reporter.release();
    reporter.report({ state: "working" });
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("keeps sequence numbers increasing across reporter instances", async () => {
    const first = createHerdrReporter(env);
    first.report({ state: "idle" });
    await complete(0);
    const second = createHerdrReporter(env);
    second.report({ state: "working" });
    expect(Number(option(1, "--seq"))).toBeGreaterThan(
      Number(option(0, "--seq")),
    );
    await complete(1);
  });
});
