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
