import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PerCommandShell } from "./perCommandShell";

const mocks = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock("node:child_process", () => ({ spawn: mocks.spawn }));

const platform = Object.getOwnPropertyDescriptor(process, "platform");

beforeEach(() => {
  vi.useFakeTimers();
  Object.defineProperty(process, "platform", { value: "win32" });
  mocks.spawn.mockReset();
});

afterEach(() => {
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

describe("PerCommandShell Windows termination", () => {
  it("settles a natural failure as soon as its output closes", async () => {
    const { child, shell } = fixture();
    const finished = vi.fn();
    const pending = shell.execute("exit 7").then(finished);
    await vi.advanceTimersByTimeAsync(0);
    child.stdout.write("partial output");
    child.emit("close", 7);
    await vi.advanceTimersByTimeAsync(0);

    expect(finished).toHaveBeenCalledWith(
      expect.objectContaining({
        exitCode: 7,
        stdout: "partial output",
        cleanupUnconfirmed: true,
      }),
    );
    expect(vi.getTimerCount()).toBe(0);
    await pending;
    await shell.dispose();
  });

  it.each([
    "abort",
    "cancel",
    "timeout",
  ])("settles %s on leader close without a TERM grace", async (cause) => {
    const { child, shell } = fixture();
    const controller = new AbortController();
    const finished = vi.fn();
    const pending = shell
      .execute("running", { abortSignal: controller.signal, timeoutSeconds: 1 })
      .then(finished);
    await vi.advanceTimersByTimeAsync(0);
    child.stdout.write("prefix");
    if (cause === "abort") controller.abort();
    else if (cause === "cancel") shell.cancelCurrentCommand();
    else await vi.advanceTimersByTimeAsync(1_000);
    expect(child.kill).toHaveBeenCalledOnce();
    child.emit("close", 1);
    await vi.advanceTimersByTimeAsync(0);

    expect(finished).toHaveBeenCalledWith(
      expect.objectContaining({
        exitCode: cause === "timeout" ? 124 : 130,
        timedOut: cause === "timeout",
        stdout: "prefix",
        cleanupUnconfirmed: true,
      }),
    );
    expect(vi.getTimerCount()).toBe(0);
    await pending;
    await shell.dispose();
  });

  it("bounds missing leader acknowledgement to the short exit window", async () => {
    const { child, shell } = fixture();
    const finished = vi.fn();
    const pending = shell.execute("running").then(finished);
    await vi.advanceTimersByTimeAsync(0);
    shell.cancelCurrentCommand();
    await vi.advanceTimersByTimeAsync(249);
    expect(finished).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);

    expect(finished).toHaveBeenCalledWith(
      expect.objectContaining({ exitCode: 130, cleanupUnconfirmed: true }),
    );
    expect(child.kill).toHaveBeenCalledOnce();
    expect(child.stdout.destroyed).toBe(true);
    expect(child.unref).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
    await pending;
    await shell.dispose();
  });
});
