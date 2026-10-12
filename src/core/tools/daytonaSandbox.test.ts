import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDaytonaExecutionSandbox } from "./daytonaSandbox";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
  vi.useRealTimers();
});

function fakeProcess() {
  return {
    createSession: vi.fn(async (_id: string) => {}),
    executeSessionCommand: vi.fn(
      async (
        _id: string,
        _request: { command: string; runAsync?: boolean },
        _timeout?: number,
      ) => ({ cmdId: "command", stdout: "out", stderr: "err", exitCode: 7 }),
    ),
    deleteSession: vi.fn(async (_id: string) => {}),
  };
}

describe("Daytona execution transport", () => {
  it("preserves streams and keeps background processes alive until transport disposal", async () => {
    const process = fakeProcess();
    const sandbox = createDaytonaExecutionSandbox(process);
    expect(await sandbox.execute("test-command", { timeout: 45 })).toEqual({
      stdout: "out",
      stderr: "err",
      exitCode: 7,
      success: false,
    });
    const id = process.createSession.mock.calls[0][0];
    expect(process.executeSessionCommand).toHaveBeenCalledWith(
      id,
      expect.objectContaining({ runAsync: false }),
      45,
    );
    expect(process.deleteSession).not.toHaveBeenCalled();
    await sandbox[Symbol.asyncDispose]();
    expect(process.deleteSession).toHaveBeenCalledWith(id);
    await expect(sandbox.execute("after-disposal")).rejects.toThrow("disposed");
  });

  it("keeps cwd and environment values literal across the remote shell", async () => {
    const directory = mkdtempSync(join(tmpdir(), "apex-transport-'"));
    directories.push(directory);
    const marker = join(directory, "injected");
    const value = `literal ' $(touch "${marker}")\nsecond line`;
    const process = fakeProcess();
    process.executeSessionCommand.mockImplementation(async (_id, request) => ({
      cmdId: "command",
      stdout: execFileSync("/bin/bash", ["-c", request.command], {
        encoding: "utf8",
      }),
      stderr: "",
      exitCode: 0,
    }));
    const sandbox = createDaytonaExecutionSandbox(process);
    const result = await sandbox.execute("printf '%s' \"$EPISODE_VALUE\"", {
      cwd: directory,
      envVars: { EPISODE_VALUE: value },
    });
    expect(result.stdout).toBe(value);
    expect(existsSync(marker)).toBe(false);
    await sandbox[Symbol.asyncDispose]();
  });

  it("rejects malformed environment before creating a remote session", async () => {
    const process = fakeProcess();
    await expect(
      createDaytonaExecutionSandbox(process).execute("true", {
        envVars: { "X; touch /tmp/invalid": "bad" },
      }),
    ).rejects.toThrow("Invalid sandbox command environment");
    expect(process.createSession).not.toHaveBeenCalled();
  });

  it("does not turn a missing terminal status into success", async () => {
    const process = fakeProcess();
    process.executeSessionCommand.mockResolvedValue({
      cmdId: "command",
      stdout: "",
      stderr: "",
      exitCode: null,
    } as never);
    await expect(
      createDaytonaExecutionSandbox(process).execute("true"),
    ).rejects.toThrow("terminal exit code");
    expect(process.deleteSession).toHaveBeenCalledOnce();
  });

  it("releases the remote session on cancellation without retrying execution", async () => {
    const process = fakeProcess();
    let executing!: () => void;
    const started = new Promise<void>((resolve) => {
      executing = resolve;
    });
    process.executeSessionCommand.mockImplementation(async () => {
      executing();
      return new Promise<never>(() => {});
    });
    const controller = new AbortController();
    const running = createDaytonaExecutionSandbox(process).execute("sleep 60", {
      abortSignal: controller.signal,
    });
    await started;
    controller.abort(new Error("cancelled by test"));
    await expect(running).rejects.toThrow("cancelled by test");
    expect(process.executeSessionCommand).toHaveBeenCalledOnce();
    expect(process.deleteSession).toHaveBeenCalledOnce();
  });

  it("cancels a stuck session creation and reaps the owned session", async () => {
    const process = fakeProcess();
    let creating!: () => void;
    const started = new Promise<void>((resolve) => {
      creating = resolve;
    });
    process.createSession.mockImplementation(async () => {
      creating();
      return new Promise<never>(() => {});
    });
    const controller = new AbortController();
    const running = createDaytonaExecutionSandbox(process).execute("true", {
      abortSignal: controller.signal,
    });
    await started;
    controller.abort(new Error("cancelled by test"));
    await expect(running).rejects.toThrow("cancelled by test");
    expect(process.executeSessionCommand).not.toHaveBeenCalled();
    expect(process.deleteSession).toHaveBeenCalledOnce();
  });

  it("reaps a session whose create lands after cancellation", async () => {
    const process = fakeProcess();
    let finishCreate!: () => void;
    let creating!: () => void;
    const started = new Promise<void>((resolve) => {
      creating = resolve;
    });
    process.createSession.mockImplementation(() => {
      creating();
      return new Promise<void>((resolve) => {
        finishCreate = resolve;
      });
    });
    process.deleteSession.mockRejectedValueOnce(
      Object.assign(new Error("missing"), { statusCode: 404 }),
    );
    const controller = new AbortController();
    const sandbox = createDaytonaExecutionSandbox(process);
    const running = sandbox.execute("true", {
      abortSignal: controller.signal,
    });
    await started;
    controller.abort(new Error("cancelled by test"));
    await expect(running).rejects.toThrow("cancelled by test");
    expect(process.deleteSession).toHaveBeenCalledOnce();
    finishCreate();
    await vi.waitFor(() =>
      expect(process.deleteSession).toHaveBeenCalledTimes(2),
    );
    await sandbox[Symbol.asyncDispose]();
    expect(process.deleteSession).toHaveBeenCalledTimes(2);
  });

  it("bounds an unresponsive execution and reaps the owned session", async () => {
    vi.useFakeTimers();
    const process = fakeProcess();
    process.executeSessionCommand.mockImplementation(
      () => new Promise<never>(() => {}),
    );
    const result = createDaytonaExecutionSandbox(process).execute(
      "sleep infinity",
      { timeout: 1 },
    );
    const assertion = expect(result).rejects.toThrow("exceeded 1 seconds");
    await vi.advanceTimersByTimeAsync(6_001);
    await assertion;
    expect(process.deleteSession).toHaveBeenCalledOnce();
  });

  it("preserves the command timeout after slow session creation", async () => {
    vi.useFakeTimers();
    const process = fakeProcess();
    process.createSession.mockImplementation(
      () => new Promise<void>((resolve) => setTimeout(resolve, 10_000)),
    );
    process.executeSessionCommand.mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(
            () =>
              resolve({
                cmdId: "command",
                stdout: "finished",
                stderr: "",
                exitCode: 0,
              }),
            9_000,
          ),
        ),
    );
    const sandbox = createDaytonaExecutionSandbox(process);
    const outcome = sandbox.execute("slow-command", { timeout: 10 }).then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    );
    await vi.advanceTimersByTimeAsync(19_000);
    expect(await outcome).toEqual({
      result: { stdout: "finished", stderr: "", exitCode: 0, success: true },
    });
    expect(process.deleteSession).not.toHaveBeenCalled();
    await sandbox[Symbol.asyncDispose]();
  });

  it("bounds session creation before a command starts", async () => {
    vi.useFakeTimers();
    const process = fakeProcess();
    process.createSession.mockImplementation(
      () => new Promise<never>(() => {}),
    );
    const sandbox = createDaytonaExecutionSandbox(process);
    const assertion = expect(
      sandbox.execute("never-started", { timeout: 1 }),
    ).rejects.toThrow("exceeded 1 seconds");
    await vi.advanceTimersByTimeAsync(6_001);
    await assertion;
    expect(process.executeSessionCommand).not.toHaveBeenCalled();
    expect(process.deleteSession).toHaveBeenCalledOnce();
    await sandbox[Symbol.asyncDispose]();
  });

  it("tries cleanup after an ambiguous create, preserving the create error on 404", async () => {
    const process = fakeProcess();
    process.createSession.mockRejectedValue(new Error("connection lost"));
    process.deleteSession.mockRejectedValue(
      Object.assign(new Error("missing"), { statusCode: 404 }),
    );
    await expect(
      createDaytonaExecutionSandbox(process).execute("true"),
    ).rejects.toThrow("connection lost");
    expect(process.executeSessionCommand).not.toHaveBeenCalled();
    expect(process.deleteSession).toHaveBeenCalledOnce();
  });
});

describe("Daytona execution capacity", () => {
  type DeferredResult = {
    cmdId: string;
    stdout: string;
    stderr: string;
    exitCode: number;
  };

  function success(): DeferredResult {
    return { cmdId: "command", stdout: "done", stderr: "", exitCode: 0 };
  }

  function deferredProcess() {
    const process = fakeProcess();
    const finish = new Map<string, (result: DeferredResult) => void>();
    process.executeSessionCommand.mockImplementation(
      (id: string) =>
        new Promise<DeferredResult>((resolve) => {
          finish.set(id, resolve);
        }),
    );
    return { process, finish };
  }

  function settle<T>(promise: Promise<T>) {
    return promise.then(
      (value: T) => ({ error: undefined as undefined, value }),
      (error: unknown) => ({ error, value: undefined as undefined }),
    );
  }

  function sessionAt(
    process: ReturnType<typeof fakeProcess>,
    index: number,
  ): string {
    const id = process.createSession.mock.calls[index]?.[0];
    if (id === undefined) throw new Error(`no session at call ${index}`);
    return id;
  }

  it("keeps commands unbounded when no maxConcurrent is declared", async () => {
    const process = fakeProcess();
    process.executeSessionCommand.mockImplementation(
      () => new Promise<never>(() => {}),
    );
    const sandbox = createDaytonaExecutionSandbox(process);
    // 64 in flight would expose any accidental default cap (8 or 32).
    const outcomes = Array.from({ length: 64 }, (_, index) =>
      settle(sandbox.execute(`command-${index}`)),
    );
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(64),
    );
    expect(process.createSession).toHaveBeenCalledTimes(64);
    await sandbox[Symbol.asyncDispose]();
    for (const outcome of await Promise.all(outcomes)) {
      expect((outcome.error as { name?: string }).name).toBe("AbortError");
    }
  });

  it("bounds in-flight commands and admits queued ones as permits free", async () => {
    const { process, finish } = deferredProcess();
    const sandbox = createDaytonaExecutionSandbox(process, undefined, {
      maxConcurrent: 2,
    });
    const outcomes = [1, 2, 3, 4].map((index) =>
      settle(sandbox.execute(`command-${index}`)),
    );
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(2),
    );
    // FIFO admission: freeing the first permit admits the third command.
    finish.get(sessionAt(process, 0))?.(success());
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(3),
    );
    expect(process.executeSessionCommand.mock.calls[2][1].command).toContain(
      "command-3",
    );
    // A successful command keeps its session alive but holds no permit.
    expect(process.deleteSession).not.toHaveBeenCalled();
    finish.get(sessionAt(process, 1))?.(success());
    finish.get(sessionAt(process, 2))?.(success());
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(4),
    );
    finish.get(sessionAt(process, 3))?.(success());
    for (const outcome of await Promise.all(outcomes)) {
      expect(outcome.error).toBeUndefined();
      expect(outcome.value?.success).toBe(true);
    }
    await sandbox[Symbol.asyncDispose]();
    expect(process.deleteSession).toHaveBeenCalledTimes(4);
  });

  it("starts the command timeout at admission, not while queued", async () => {
    vi.useFakeTimers();
    const process = fakeProcess();
    process.executeSessionCommand.mockImplementation(
      () => new Promise<never>(() => {}),
    );
    const sandbox = createDaytonaExecutionSandbox(process, undefined, {
      maxConcurrent: 1,
    });
    const first = sandbox.execute("first", { timeout: 10 });
    const second = sandbox.execute("second", { timeout: 1 });
    const firstAssertion = expect(first).rejects.toThrow("exceeded 10 seconds");
    const secondAssertion =
      expect(second).rejects.toThrow("exceeded 1 seconds");
    // Past second's deadline had it armed at enqueue time; it must still wait.
    await vi.advanceTimersByTimeAsync(6_001);
    expect(process.executeSessionCommand).toHaveBeenCalledTimes(1);
    // First's own deadline frees the permit; second's deadline starts now.
    await vi.advanceTimersByTimeAsync(9_000);
    await firstAssertion;
    await vi.advanceTimersByTimeAsync(1);
    expect(process.executeSessionCommand).toHaveBeenCalledTimes(2);
    expect(process.createSession).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(6_001);
    await secondAssertion;
    expect(process.deleteSession).toHaveBeenCalledTimes(2);
    await sandbox[Symbol.asyncDispose]();
    expect(process.deleteSession).toHaveBeenCalledTimes(2);
  });

  it("aborts a queued command without dispatching it and never replays it", async () => {
    const { process, finish } = deferredProcess();
    const sandbox = createDaytonaExecutionSandbox(process, undefined, {
      maxConcurrent: 1,
    });
    const controller = new AbortController();
    const first = settle(sandbox.execute("first"));
    const second = settle(
      sandbox.execute("second", { abortSignal: controller.signal }),
    );
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(1),
    );
    controller.abort(new Error("cancelled by test"));
    expect((await second).error).toMatchObject({
      message: "cancelled by test",
    });
    // The freed permit goes to a later command, not a replay of the aborted one.
    const third = settle(sandbox.execute("third"));
    finish.get(sessionAt(process, 0))?.(success());
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(2),
    );
    finish.get(sessionAt(process, 1))?.(success());
    expect((await first).error).toBeUndefined();
    expect((await third).error).toBeUndefined();
    expect(process.createSession).toHaveBeenCalledTimes(2);
    await sandbox[Symbol.asyncDispose]();
  });

  it("holds a permit until a failed command's cleanup settles", async () => {
    const process = fakeProcess();
    process.executeSessionCommand
      .mockResolvedValueOnce({
        cmdId: "command",
        stdout: "",
        stderr: "",
        exitCode: null,
      } as never)
      .mockImplementation(async () => success());
    let finishDelete!: () => void;
    process.deleteSession.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishDelete = resolve;
        }),
    );
    const sandbox = createDaytonaExecutionSandbox(process, undefined, {
      maxConcurrent: 1,
    });
    const first = settle(sandbox.execute("first"));
    const second = settle(sandbox.execute("second"));
    await vi.waitFor(() =>
      expect(process.deleteSession).toHaveBeenCalledOnce(),
    );
    // The reap is still pending; the permit stays held and the queued call
    // must not dispatch until the deletion settles.
    expect(process.createSession).toHaveBeenCalledTimes(1);
    expect(process.executeSessionCommand).toHaveBeenCalledTimes(1);
    finishDelete();
    expect((await first).error).toMatchObject({
      message: expect.stringContaining("terminal exit code"),
    });
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(2),
    );
    expect(process.createSession).toHaveBeenCalledTimes(2);
    expect((await second).error).toBeUndefined();
    await sandbox[Symbol.asyncDispose]();
  });

  it("rejects queued commands at disposal without dispatching them", async () => {
    const process = fakeProcess();
    process.executeSessionCommand.mockImplementation(
      () => new Promise<never>(() => {}),
    );
    const sandbox = createDaytonaExecutionSandbox(process, undefined, {
      maxConcurrent: 1,
    });
    const outcomes = [1, 2, 3].map((index) =>
      settle(sandbox.execute(`command-${index}`)),
    );
    await vi.waitFor(() =>
      expect(process.executeSessionCommand).toHaveBeenCalledTimes(1),
    );
    await sandbox[Symbol.asyncDispose]();
    for (const outcome of await Promise.all(outcomes)) {
      expect((outcome.error as { name?: string }).name).toBe("AbortError");
    }
    expect(process.createSession).toHaveBeenCalledTimes(1);
    expect(process.deleteSession).toHaveBeenCalledOnce();
    const after = settle(sandbox.execute("after-disposal"));
    expect((await after).error).toMatchObject({
      message: expect.stringContaining("disposed"),
    });
  });

  it("rejects an invalid declared maxConcurrent", () => {
    const process = fakeProcess();
    for (const maxConcurrent of [
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      expect(() =>
        createDaytonaExecutionSandbox(process, undefined, { maxConcurrent }),
      ).toThrow("maxConcurrent");
    }
  });
});
