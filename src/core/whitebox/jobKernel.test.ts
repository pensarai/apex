import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { createWhiteboxJobKernel } from "./jobKernel";

const load = createRequire(import.meta.url);
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});
it("preserves synchronous Windows cmd quoting and bounded native capture", () => {
  vi.useFakeTimers();
  vi.spyOn(process, "platform", "get").mockReturnValue("win32");
  const root = mkdtempSync(join(tmpdir(), "apex-job-windows-"));
  const child = Object.assign(new EventEmitter(), {
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    kill: vi.fn(),
    pid: 123,
  });
  const spawn = vi.fn(() => child);
  const spawnSync = vi.fn(() => ({
    status: 0,
    stderr: "",
    error: undefined as Error | undefined,
  }));
  const kernel = createWhiteboxJobKernel(
    Object.assign(
      (name: string) =>
        name === "node:child_process" ? { spawn, spawnSync } : load(name),
      load,
    ),
  );
  try {
    const command = 'node "a b\\odd\'&name.js"';
    const record = kernel.startWhiteboxJob({
      session: { id: "windows", logsPath: root },
      command,
      cwd: root,
      timeoutSeconds: 10,
    });
    expect(spawn).toHaveBeenCalledWith(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", `"${command}"`],
      {
        cwd: root,
        stdio: ["ignore", "pipe", "pipe"],
        detached: false,
        windowsVerbatimArguments: true,
      },
    );
    expect(record.status).toBe("running");
    expect(kernel.pollWhiteboxJob(record.id, "other")).toBeUndefined();
    child.stdout.emit("data", Buffer.alloc(12 * 1024 * 1024, "x"));
    expect(statSync(record.logPath).size).toBe(10 * 1024 * 1024);
    expect(kernel.readWhiteboxJobLog(record.id, "windows").content).toContain(
      "job log truncated",
    );
    spawnSync.mockReturnValueOnce({
      status: 1,
      stderr: "",
      error: new Error("taskkill unavailable"),
    });
    expect(() => kernel.stopWhiteboxJob(record.id, "windows")).toThrow(
      "taskkill unavailable",
    );
    expect(kernel.pollWhiteboxJob(record.id, "windows")?.status).toBe(
      "running",
    );
    expect(kernel.stopWhiteboxJob(record.id, "windows")?.status).toBe(
      "stopped",
    );
    expect(spawnSync).toHaveBeenLastCalledWith(
      "taskkill.exe",
      ["/pid", "123", "/t", "/f"],
      { windowsHide: true, timeout: 2000, encoding: "utf8" },
    );
    expect(child.kill).not.toHaveBeenCalled();
    child.emit("close", null);
    vi.advanceTimersByTime(2000);
    expect(child.kill).not.toHaveBeenCalled();
    expect(kernel.lifecycle(record.id).drained).toBe(true);
    vi.advanceTimersByTime(60000);
    expect(kernel.pollWhiteboxJob(record.id, "windows")).toBeUndefined();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
