import {
  chmodSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const fakeChild = () => {
  const listeners = new Map<string, (value?: unknown) => void>();
  return {
    once: (event: string, handler: (value?: unknown) => void) => {
      listeners.set(event, handler);
    },
    unref: vi.fn(),
    kill: vi.fn(),
    __emit: (event: string, value?: unknown) => {
      listeners.get(event)?.(value);
    },
  };
};

const spawnMock = vi.hoisted(() => vi.fn((..._args: unknown[]) => fakeChild()));
const resolveWorkerEndpoint = vi.hoisted(() => vi.fn());
const workerRequest = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  spawn: spawnMock as unknown as typeof import("node:child_process").spawn,
}));
vi.mock("./localWorkerEndpoint", () => ({ resolveWorkerEndpoint }));
vi.mock("./localWorkerTransport", () => ({ workerRequest }));

const { launchLocalWorker, resolveWorkerExecutable } = await import(
  "./launchLocalWorker"
);

const tempDirs: string[] = [];
const workerDir = "/tmp/launch-worker-endpoints";

function endpointPaths(root = workerDir, runId = "run_w") {
  return {
    socketPath: join(root, `${runId}.sock`),
    logPath: join(root, `${runId}.log`),
    lockDatabasePath: join(root, `${runId}.host.sqlite`),
  };
}

afterEach(() => {
  spawnMock.mockClear();
  resolveWorkerEndpoint.mockReset();
  workerRequest.mockReset();
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("launchLocalWorker", () => {
  it("waits for a settled host to retire before launching a fresh host", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir));
    workerRequest
      .mockResolvedValueOnce({ phase: "settled" })
      .mockResolvedValueOnce({ phase: "settled" })
      .mockRejectedValueOnce(
        Object.assign(new Error("gone"), { code: "ENOENT" }),
      )
      .mockResolvedValueOnce({ phase: "idle" });
    await launchLocalWorker({
      runId: "run_w",
      databasePath: "/tmp/canonical.sqlite",
      executable: { command: "pensar" },
      probeIntervalMs: 1,
    });
    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(workerRequest).toHaveBeenCalledTimes(4);
    expect(workerRequest.mock.invocationCallOrder[2]).toBeLessThan(
      spawnMock.mock.invocationCallOrder[0],
    );
  });

  it("bounds retirement waiting without spawning beside a live host", async () => {
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths());
    workerRequest.mockResolvedValue({ phase: "settled" });
    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
        probeIntervalMs: 1,
        startupTimeoutMs: 5,
      }),
    ).rejects.toThrow("did not retire");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("reuses a live endpoint without spawning", async () => {
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths());
    workerRequest.mockResolvedValue({ protocolVersion: 1, phase: "executing" });

    const result = await launchLocalWorker({
      runId: "run_w",
      databasePath: "/tmp/canonical.sqlite",
      executable: { command: "pensar" },
    });

    expect(workerRequest).toHaveBeenCalledTimes(1);
    expect(workerRequest).toHaveBeenCalledWith(
      `${workerDir}/run_w.sock`,
      { protocolVersion: 1, method: "snapshot" },
      { timeoutMs: 2_000 },
    );
    expect(spawnMock).not.toHaveBeenCalled();
    expect(result).toEqual({
      socketPath: `${workerDir}/run_w.sock`,
      logPath: `${workerDir}/run_w.log`,
    });
  });

  it("spawns detached for a refused endpoint and waits for readiness", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_new"));
    let probes = 0;
    workerRequest.mockImplementation(async () => {
      probes += 1;
      if (probes < 3) {
        throw Object.assign(new Error("connect ECONNREFUSED"), {
          code: "ECONNREFUSED",
        });
      }
      return { protocolVersion: 1, phase: "idle" };
    });

    const result = await launchLocalWorker({
      runId: "run_new",
      databasePath: "/tmp/nested/../canonical.sqlite",
      executable: { command: "/usr/local/bin/pensar", args: ["--extra"] },
      probeIntervalMs: 1,
    });

    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [command, args, options] = spawnMock.mock.calls[0] as unknown as [
      string,
      string[],
      { detached: boolean; stdio: unknown[] },
    ];
    expect(command).toBe("/usr/local/bin/pensar");
    expect(args).toEqual([
      "--extra",
      "agent-runs",
      "worker",
      "--run",
      "run_new",
      "--store",
      "/tmp/canonical.sqlite",
    ]);
    expect(options.detached).toBe(true);
    expect(options.stdio[0]).toBe("ignore");
    expect(typeof options.stdio[1]).toBe("number");
    expect(options.stdio[1]).toBe(options.stdio[2]);
    expect(probes).toBe(3);
    expect(result.socketPath).toBe(`${dir}/run_new.sock`);
    expect(result.logPath).toBe(`${dir}/run_new.log`);
    expect(
      (spawnMock.mock.results[0].value as { unref: ReturnType<typeof vi.fn> })
        .unref,
    ).toHaveBeenCalled();
  });

  it("propagates a live-but-incompatible peer without spawning", async () => {
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths());
    const incompatible = new Error("worker responded with protocolVersion 99");
    workerRequest.mockRejectedValue(incompatible);

    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toBe(incompatible);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("propagates a permission failure without spawning", async () => {
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths());
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connect EACCES"), { code: "EACCES" }),
    );

    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toThrow("EACCES");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("fails when the worker log cannot be opened", async () => {
    resolveWorkerEndpoint.mockResolvedValue(
      endpointPaths("/nonexistent-worker-dir", "run_w"),
    );
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connect ENOENT"), { code: "ENOENT" }),
    );

    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toThrow(/\/nonexistent-worker-dir\/run_w\.log/);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("surfaces a spawn error promptly instead of probing to timeout", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_w"));
    workerRequest.mockImplementation(async () => {
      const child = spawnMock.mock.results.at(-1)?.value as {
        __emit: (event: string, value?: unknown) => void;
      };
      child?.__emit("error", new Error("spawn pensar ENOENT"));
      throw Object.assign(new Error("connect ECONNREFUSED"), {
        code: "ECONNREFUSED",
      });
    });

    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
        probeIntervalMs: 1,
      }),
    ).rejects.toThrow(/failed to start: spawn pensar ENOENT/);
  });

  it("keeps probing after our child exits: a concurrently starting peer still wins", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_w"));
    let probes = 0;
    workerRequest.mockImplementation(async () => {
      probes += 1;
      if (probes === 2) {
        // Our child loses the host lock and exits — not proof the endpoint
        // will stay absent; a concurrent worker may still be starting.
        const child = spawnMock.mock.results.at(-1)?.value as {
          __emit: (event: string, value?: unknown) => void;
        };
        child?.__emit("exit", 1);
      }
      if (probes < 4) {
        throw Object.assign(new Error("connect ECONNREFUSED"), {
          code: "ECONNREFUSED",
        });
      }
      // The concurrent peer becomes ready; the launcher succeeds.
      return { protocolVersion: 1, phase: "idle" };
    });

    const result = await launchLocalWorker({
      runId: "run_w",
      databasePath: "/tmp/canonical.sqlite",
      executable: { command: "pensar" },
      probeIntervalMs: 1,
    });

    expect(probes).toBe(4);
    expect(result.socketPath).toBe(`${dir}/run_w.sock`);
  });

  it("reports the exited child and log path when the deadline passes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_w"));
    workerRequest.mockImplementation(async () => {
      const child = spawnMock.mock.results.at(-1)?.value as {
        __emit: (event: string, value?: unknown) => void;
      };
      child?.__emit("exit", 3);
      throw Object.assign(new Error("connect ECONNREFUSED"), {
        code: "ECONNREFUSED",
      });
    });

    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
        startupTimeoutMs: 25,
        probeIntervalMs: 5,
      }),
    ).rejects.toThrow(
      /did not become ready within 25ms: our worker process exited \(code 3\); log: .*run_w\.log/,
    );
  });

  it("times out explicitly without killing the child", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_slow"));
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connect ECONNREFUSED"), {
        code: "ECONNREFUSED",
      }),
    );

    await expect(
      launchLocalWorker({
        runId: "run_slow",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
        startupTimeoutMs: 30,
        probeIntervalMs: 5,
      }),
    ).rejects.toThrow(/did not become ready within 30ms/);

    const child = spawnMock.mock.results[0].value as {
      kill: ReturnType<typeof vi.fn>;
      unref: ReturnType<typeof vi.fn>;
    };
    expect(child.kill).not.toHaveBeenCalled();
    expect(child.unref).toHaveBeenCalled();
  });

  it("rejects invalid inputs before resolving or probing anything", async () => {
    await expect(
      launchLocalWorker({
        runId: "run_w",
        databasePath: "runs.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toThrow(/database path must be absolute/);

    await expect(
      launchLocalWorker({
        runId: "",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toThrow(/run id is required/);

    expect(resolveWorkerEndpoint).not.toHaveBeenCalled();
    expect(workerRequest).not.toHaveBeenCalled();
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

describe("resolveWorkerExecutable", () => {
  it("compiled Bun: the binary itself, no script arg (virtual Bun.main)", () => {
    expect(
      resolveWorkerExecutable({
        execPath: "/opt/pensar/bin/pensar",
        argv1: "/$bunfs/root/pensar",
        bunMain: "/$bunfs/root/pensar",
      }),
    ).toEqual({ command: "/opt/pensar/bin/pensar" });
  });

  it("compiled Bun: detected via argv[1] when Bun.main is unavailable", () => {
    expect(
      resolveWorkerExecutable({
        execPath: "/opt/pensar/bin/pensar",
        argv1: "/$bunfs/root/pensar",
      }),
    ).toEqual({ command: "/opt/pensar/bin/pensar" });
  });

  it("source Bun: re-runs the absolute argv[1] under the bun binary", () => {
    expect(
      resolveWorkerExecutable({
        execPath: "/Users/kyle/.bun/bin/bun",
        argv1: "/repo/src/cli.ts",
        bunMain: "/repo/src/cli.ts",
      }),
    ).toEqual({
      command: "/Users/kyle/.bun/bin/bun",
      args: ["/repo/src/cli.ts"],
    });
  });

  it("Node: re-runs the absolute argv[1] (npm wrapper already rewritten)", () => {
    expect(
      resolveWorkerExecutable({
        execPath: "/usr/local/bin/node",
        argv1: "/repo/build/cli.js",
      }),
    ).toEqual({ command: "/usr/local/bin/node", args: ["/repo/build/cli.js"] });
  });

  it("rejects a missing or relative argv[1] outside compiled binaries", () => {
    expect(() => resolveWorkerExecutable({ argv1: undefined })).toThrow(
      /Cannot resolve the CLI entry/,
    );
    expect(() => resolveWorkerExecutable({ argv1: "cli.js" })).toThrow(
      /Cannot resolve the CLI entry/,
    );
  });
});

describe("worker log safety", () => {
  it("rejects a symlinked log path before opening it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    const target = join(dir, "target.log");
    writeFileSync(target, "x");
    resolveWorkerEndpoint.mockResolvedValue({
      ...endpointPaths(dir, "run_sym"),
      logPath: join(dir, "sym.log"),
    });
    symlinkSync(target, join(dir, "sym.log"));
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connect ENOENT"), { code: "ENOENT" }),
    );

    await expect(
      launchLocalWorker({
        runId: "run_sym",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toThrow(/not a regular file/);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("rejects an existing log with group/other bits set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_open"));
    writeFileSync(join(dir, "run_open.log"), "old");
    chmodSync(join(dir, "run_open.log"), 0o644);
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connect ENOENT"), { code: "ENOENT" }),
    );

    await expect(
      launchLocalWorker({
        runId: "run_open",
        databasePath: "/tmp/canonical.sqlite",
        executable: { command: "pensar" },
      }),
    ).rejects.toThrow(/permissions are too broad/);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("accepts an existing owner-only log and appends", async () => {
    const dir = mkdtempSync(join(tmpdir(), "launch-worker-"));
    tempDirs.push(dir);
    resolveWorkerEndpoint.mockResolvedValue(endpointPaths(dir, "run_ok"));
    writeFileSync(join(dir, "run_ok.log"), "old");
    chmodSync(join(dir, "run_ok.log"), 0o600);
    let probes = 0;
    workerRequest.mockImplementation(async () => {
      probes += 1;
      if (probes < 2) {
        throw Object.assign(new Error("connect ECONNREFUSED"), {
          code: "ECONNREFUSED",
        });
      }
      return { protocolVersion: 1, phase: "idle" };
    });

    const result = await launchLocalWorker({
      runId: "run_ok",
      databasePath: "/tmp/canonical.sqlite",
      executable: { command: "pensar" },
      probeIntervalMs: 1,
    });

    expect(result.socketPath).toBe(`${dir}/run_ok.sock`);
    expect(spawnMock).toHaveBeenCalledTimes(1);
  });
});
