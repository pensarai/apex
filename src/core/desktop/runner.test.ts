import { describe, expect, it, vi } from "vitest";
import { runBuildManifest } from "./runner";
import type { BuildManifest, DesktopExecResult } from "./types";

const ok: DesktopExecResult = {
  stdout: "",
  stderr: "",
  exitCode: 0,
  success: true,
};
const fail: DesktopExecResult = {
  stdout: "",
  stderr: "boom",
  exitCode: 1,
  success: false,
};

function manifest(overrides: Partial<BuildManifest> = {}): BuildManifest {
  return {
    manifestVersion: 1,
    artifact: {
      id: "a1",
      filename: "app.AppImage",
      path: "/work/app.AppImage",
      format: "appimage",
      platform: "linux",
      architecture: "x64",
      sha256: null,
    },
    install: {
      mode: "appimage-direct",
      script: 'chmod +x "/work/app.AppImage"',
    },
    launch: {
      executablePath: "/work/app.AppImage",
      args: [],
      workingDirectory: null,
      environment: [],
    },
    readinessCheck: null,
    teardownScript: null,
    ...overrides,
  };
}

const noSleep = () => Promise.resolve();

describe("runBuildManifest", () => {
  it("runs install then launch then reports ready when no readiness check", async () => {
    const exec = vi.fn().mockResolvedValue(ok);
    const result = await runBuildManifest({
      exec,
      os: "linux",
      manifest: manifest(),
      sleep: noSleep,
    });
    expect(result).toEqual({
      installed: true,
      launched: true,
      ready: true,
      readinessKind: null,
    });
    // install call first, launch second
    expect(exec).toHaveBeenCalledTimes(2);
    expect(exec.mock.calls[0][0]).toContain("chmod +x");
    expect(exec.mock.calls[1][0]).toContain("app.AppImage");
  });

  it("throws when the install step fails and does not launch", async () => {
    const exec = vi.fn().mockResolvedValue(fail);
    await expect(
      runBuildManifest({
        exec,
        os: "linux",
        manifest: manifest(),
        sleep: noSleep,
      }),
    ).rejects.toThrow(/Install step failed/);
    expect(exec).toHaveBeenCalledTimes(1);
  });

  it("polls a process readiness probe until it succeeds", async () => {
    // install ok, launch ok, probe fails once then succeeds.
    const exec = vi
      .fn()
      .mockResolvedValueOnce(ok) // install
      .mockResolvedValueOnce(ok) // launch
      .mockResolvedValueOnce(fail) // probe #1
      .mockResolvedValueOnce(ok); // probe #2
    const result = await runBuildManifest({
      exec,
      os: "linux",
      manifest: manifest({
        readinessCheck: { kind: "process", process: "app", timeoutSeconds: 30 },
      }),
      sleep: noSleep,
      pollIntervalMs: 1,
    });
    expect(result.ready).toBe(true);
    expect(result.readinessKind).toBe("process");
    expect(exec).toHaveBeenCalledTimes(4);
  });

  it("honors a sleep readiness check without a probe", async () => {
    const exec = vi.fn().mockResolvedValue(ok);
    const sleep = vi.fn().mockResolvedValue(undefined);
    const result = await runBuildManifest({
      exec,
      os: "linux",
      manifest: manifest({ readinessCheck: { kind: "sleep", seconds: 5 } }),
      sleep,
    });
    expect(result.ready).toBe(true);
    expect(sleep).toHaveBeenCalledWith(5000);
    // only install + launch hit exec; sleep is not a probe
    expect(exec).toHaveBeenCalledTimes(2);
  });

  it("skips launch when there is no executable", async () => {
    const exec = vi.fn().mockResolvedValue(ok);
    const result = await runBuildManifest({
      exec,
      os: "windows",
      manifest: manifest({
        launch: {
          executablePath: null,
          args: [],
          workingDirectory: null,
          environment: [],
        },
      }),
      sleep: noSleep,
    });
    expect(result.launched).toBe(false);
    expect(exec).toHaveBeenCalledTimes(1); // install only
  });

  it("rejects an unsupported manifest version", async () => {
    const exec = vi.fn().mockResolvedValue(ok);
    await expect(
      runBuildManifest({
        exec,
        os: "linux",
        manifest: manifest({ manifestVersion: 99 }),
        sleep: noSleep,
      }),
    ).rejects.toThrow(/Unsupported build manifest version 99/);
    expect(exec).not.toHaveBeenCalled();
  });
});
