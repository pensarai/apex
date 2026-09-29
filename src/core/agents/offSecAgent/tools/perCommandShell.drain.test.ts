import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PerCommandShell } from "./perCommandShell";

const mocks = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock("node:child_process", () => ({ spawn: mocks.spawn }));

const platform = Object.getOwnPropertyDescriptor(process, "platform");

beforeEach(() => {
  vi.useFakeTimers();
  Object.defineProperty(process, "platform", { value: "linux" });
  mocks.spawn.mockReset();
  vi.spyOn(process, "kill").mockImplementation((_pid, signal) => {
    if (signal === 0) throw Object.assign(new Error("gone"), { code: "ESRCH" });
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  if (platform) Object.defineProperty(process, "platform", platform);
});

function fixture() {
  const child = Object.assign(new EventEmitter(), {
    pid: 123,
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    kill: vi.fn(() => true),
    unref: vi.fn(),
  });
  mocks.spawn.mockReturnValue(child);
  return { child, shell: new PerCommandShell() };
}

describe("PerCommandShell termination output drain", () => {
  it.each([
    "timeout",
    "abort",
    "cancel",
    "dispose",
  ])("keeps unread stdout and stderr after the group is gone on %s", async (cause) => {
    const { child, shell } = fixture();
    const ac = new AbortController();
    const finished = vi.fn();
    const pending = shell
      .execute("running", {
        timeoutSeconds: 1,
        abortSignal: ac.signal,
      })
      .then(finished);
    await vi.advanceTimersByTimeAsync(0);
    child.stdout.write("prefix-");
    if (cause === "timeout") await vi.advanceTimersByTimeAsync(1_000);
    else if (cause === "abort") ac.abort();
    else if (cause === "dispose") void shell.dispose();
    else shell.cancelCurrentCommand();

    // ESRCH can precede delivery of the final pipe data and close event.
    await vi.advanceTimersByTimeAsync(25);
    expect(finished).not.toHaveBeenCalled();
    child.stdout.write("last stdout");
    child.stderr.write("last stderr");
    child.emit("close", null);
    await vi.advanceTimersByTimeAsync(0);

    expect(finished).toHaveBeenCalledWith(
      expect.objectContaining({
        stdout: "prefix-last stdout",
        stderr: cause === "timeout" ? "last stderr" : "last stderr\n(aborted)",
        exitCode: cause === "timeout" ? 124 : 130,
        cleanupUnconfirmed: false,
      }),
    );
    expect(vi.getTimerCount()).toBe(0);
    await pending;
    await shell.dispose();
  });

  it("bounds the drain when an escaped process keeps an inherited pipe open", async () => {
    const { child, shell } = fixture();
    const finished = vi.fn();
    const pending = shell.execute("running").then(finished);
    await vi.advanceTimersByTimeAsync(0);
    shell.cancelCurrentCommand();
    await vi.advanceTimersByTimeAsync(25);
    child.stdout.write("late buffered output");
    await vi.advanceTimersByTimeAsync(249);
    expect(finished).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);

    expect(finished).toHaveBeenCalledWith(
      expect.objectContaining({
        stdout: "late buffered output",
        stderr: expect.stringContaining("output drain unconfirmed"),
        exitCode: 130,
        cleanupUnconfirmed: false,
      }),
    );
    expect(child.stdout.destroyed).toBe(true);
    expect(child.stderr.destroyed).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
    await pending;
    await shell.dispose();
  });
});
