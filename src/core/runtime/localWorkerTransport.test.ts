import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WorkerSnapshot } from "./localWorkerProtocol";
import { serveWorkerTransport, workerRequest } from "./localWorkerTransport";

// Real sockets, real workerRequest — only raw-wire cases bypass the client.

type WorkerFailure = { message: string; code?: string; uncertain?: boolean };

async function expectFailure(
  promise: Promise<unknown>,
): Promise<WorkerFailure> {
  return promise.then(
    () => {
      throw new Error("expected the worker request to fail");
    },
    (cause: unknown) => {
      expect(cause).toBeInstanceOf(Error);
      const error = cause as WorkerFailure & { name?: string };
      return {
        message: error.message,
        ...(error.code !== undefined ? { code: error.code } : {}),
        ...(error.uncertain !== undefined
          ? { uncertain: error.uncertain }
          : {}),
      };
    },
  );
}

function fixtureSnapshot(
  overrides: Partial<WorkerSnapshot> = {},
): WorkerSnapshot {
  return {
    protocolVersion: 1,
    workerId: "11111111-1111-4111-8111-111111111111",
    runId: "run_transport_test",
    phase: "idle",
    sequence: 0,
    observation: { record: null, context: null, control: null, approvals: [] },
    ...overrides,
  };
}

let tempDirs: string[];

function socketPath(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "worker-transport-"));
  tempDirs.push(dir);
  return path.join(dir, "worker.sock");
}

const snapshotRequest = { protocolVersion: 1, method: "snapshot" } as const;

beforeEach(() => {
  tempDirs = [];
});

afterEach(async () => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
});

describe("worker request/response roundtrip", () => {
  it("returns the served snapshot and delivers the exact parsed request", async () => {
    const socketPathName = socketPath();
    const seen: unknown[] = [];
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async (request) => {
        seen.push(request);
        return fixtureSnapshot({ sequence: 7, phase: "executing" });
      },
    });
    try {
      const snapshot = await workerRequest(socketPathName, snapshotRequest);
      expect(snapshot).toEqual(
        fixtureSnapshot({ sequence: 7, phase: "executing" }),
      );
      expect(seen).toEqual([snapshotRequest]);
    } finally {
      await server.close();
    }
  });

  it("rejects a malformed response from a live peer without a spawn-safe code", async () => {
    // Raw wire: a peer that answers with a wrong protocol version.
    const socketPathName = socketPath();
    const peer = createServer((socket) => {
      socket.on("data", () => {
        const body = JSON.stringify({ protocolVersion: 2 });
        socket.end(
          `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`,
        );
      });
    });
    await new Promise<void>((resolve) => peer.listen(socketPathName, resolve));
    try {
      await expect(
        workerRequest(socketPathName, snapshotRequest),
      ).rejects.toThrow(/not supported/);
      // No ENOENT/ECONNREFUSED: a live incompatible peer is never absent.
      const error = await expectFailure(
        workerRequest(socketPathName, snapshotRequest),
      );
      expect(error.code).toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => peer.close(() => resolve()));
    }
  });
});

describe("protocol and bounds enforcement", () => {
  it("rejects a wrong request version before invoking the handler", async () => {
    const socketPathName = socketPath();
    let handled = 0;
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async () => {
        handled += 1;
        return fixtureSnapshot();
      },
    });
    try {
      const error = await expectFailure(
        workerRequest(socketPathName, {
          protocolVersion: 2,
          method: "snapshot",
        } as never),
      );
      expect(error.message).toMatch(/not supported/i);
      expect(handled).toBe(0);
      // A 400 answer is a definitive refusal, not an uncertain mutation.
      expect(error.uncertain).toBeFalsy();
    } finally {
      await server.close();
    }
  });

  it("refuses request bodies beyond the bound on both sides", async () => {
    const socketPathName = socketPath();
    let handled = 0;
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async () => {
        handled += 1;
        return fixtureSnapshot();
      },
    });
    try {
      // Client-side pre-send bound.
      await expect(
        workerRequest(socketPathName, {
          protocolVersion: 1,
          method: "start",
          spec: { big: "x".repeat(1024 * 1024 + 256) },
        } as never),
      ).rejects.toThrow(/exceeds its bound/i);

      // Server-side raw-wire bound.
      const refused = await new Promise<number>((resolve, reject) => {
        const socket = connect(socketPathName);
        const big = "x".repeat(1024 * 1024 + 256);
        const body = JSON.stringify({
          protocolVersion: 1,
          method: "start",
          spec: { big },
        });
        socket.on("connect", () => {
          socket.write(
            `POST /rpc HTTP/1.1\r\nhost: worker\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n`,
          );
          socket.write(body);
        });
        socket.on("data", (chunk) => {
          const head = chunk.toString().split("\r\n")[0] ?? "";
          resolve(Number.parseInt(head.split(" ")[1] ?? "0", 10));
          socket.end();
        });
        socket.on("error", reject);
      });
      expect(refused).toBe(413);
      expect(handled).toBe(0);
    } finally {
      await server.close();
    }
  });

  it("refuses responses beyond the bound", async () => {
    const socketPathName = socketPath();
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async () =>
        fixtureSnapshot({
          error: { message: "x".repeat(16 * 1024 * 1024 + 1024) },
        }),
    });
    try {
      await expect(
        workerRequest(socketPathName, snapshotRequest),
      ).rejects.toThrow(/exceeded its bound/i);
    } finally {
      await server.close();
    }
  });
});

describe("concurrency cap", () => {
  it("refuses the 33rd concurrent request while 32 watches are pending", async () => {
    const socketPathName = socketPath();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async (_request, signal) => {
        await Promise.race([gate, aborted(signal)]);
        return fixtureSnapshot({ sequence: 1 });
      },
    });
    const pending: Array<Promise<WorkerSnapshot>> = [];
    try {
      for (let i = 0; i < 32; i++) {
        pending.push(
          workerRequest(socketPathName, {
            protocolVersion: 1,
            method: "watch",
          }),
        );
      }
      // Give the 32 watches time to reach the handler before the 33rd.
      await new Promise((resolve) => setTimeout(resolve, 250));
      const saturated = await expectFailure(
        workerRequest(socketPathName, snapshotRequest),
      );
      expect(saturated.message).toMatch(/unavailable or saturated/i);
      // A 503 peer is closing or saturated — typed so callers can wait it
      // out instead of treating it as a fatal peer error.
      expect(saturated.code).toBe("UNAVAILABLE");
      release();
      expect((await Promise.all(pending)).length).toBe(32);
    } finally {
      release();
      await server.close();
    }
  });
});

describe("watch lifecycle", () => {
  it("does not abort a valid watch when the request body completes", async () => {
    const socketPathName = socketPath();
    const observed: boolean[] = [];
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async (request, signal) => {
        expect(request.method).toBe("watch");
        observed.push(signal.aborted); // body fully sent before this runs
        await new Promise((resolve) => setTimeout(resolve, 250));
        observed.push(signal.aborted); // still connected
        return fixtureSnapshot({ sequence: 3 });
      },
    });
    try {
      const snapshot = await workerRequest(socketPathName, {
        protocolVersion: 1,
        method: "watch",
        cursor: { workerId: "other", sequence: 2 },
      });
      expect(snapshot.sequence).toBe(3);
      expect(observed).toEqual([false, false]);
    } finally {
      await server.close();
    }
  });

  it("releases exactly the aborted client's watch handler", async () => {
    const socketPathName = socketPath();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const releasedVia: string[] = [];
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async (request, signal) => {
        const via = await Promise.race([
          gate.then(() => "gate"),
          aborted(signal).catch(() => "abort"),
        ]);
        releasedVia.push(`${request.method}:${via}`);
        return fixtureSnapshot();
      },
    });
    const controller = new AbortController();
    const watch = workerRequest(
      socketPathName,
      { protocolVersion: 1, method: "watch" },
      { signal: controller.signal },
    );
    const bystander = workerRequest(socketPathName, {
      protocolVersion: 1,
      method: "watch",
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    controller.abort();

    const error = await expectFailure(watch);
    expect(error.message).toMatch(/cancelled/i);
    expect(error.uncertain).toBe(false);
    // Only the aborted client's handler released, via its own signal.
    await vi.waitFor(() => expect(releasedVia).toEqual(["watch:abort"]));

    release();
    expect((await bystander).protocolVersion).toBe(1);
    expect(releasedVia).toEqual(["watch:abort", "watch:gate"]);
    await server.close();
  });
});

describe("server shutdown", () => {
  it.each([
    "snapshot",
    "watch",
  ] as const)("retries one interrupted %s without treating a live endpoint as absent", async (method) => {
    const endpoint = socketPath();
    let requests = 0;
    const peer = http.createServer((_req, res) => {
      if (++requests === 1) res.destroy();
      else res.end(JSON.stringify(fixtureSnapshot()));
    });
    await new Promise<void>((resolve) => peer.listen(endpoint, resolve));
    try {
      await expect(
        workerRequest(endpoint, { protocolVersion: 1, method }),
      ).resolves.toEqual(fixtureSnapshot());
      expect(requests).toBe(2);
    } finally {
      await new Promise<void>((resolve) => peer.close(() => resolve()));
    }
  });

  it("rechecks actual absence when a retiring peer interrupts a read", async () => {
    const endpoint = socketPath();
    let requests = 0;
    const peer = http.createServer((_req, res) => {
      requests++;
      peer.close();
      res.destroy();
    });
    await new Promise<void>((resolve) => peer.listen(endpoint, resolve));
    try {
      const error = await expectFailure(
        workerRequest(endpoint, snapshotRequest),
      );
      expect(error.code).toBe("ENOENT");
      expect(error.uncertain).toBe(false);
      expect(requests).toBe(1);
    } finally {
      await new Promise<void>((resolve) => peer.close(() => resolve()));
    }
  });

  it("does not resend a mutation whose acknowledgement was lost", async () => {
    const endpoint = socketPath();
    let requests = 0;
    const peer = http.createServer((_req, res) => {
      requests++;
      res.destroy();
    });
    await new Promise<void>((resolve) => peer.listen(endpoint, resolve));
    try {
      const error = await expectFailure(
        workerRequest(endpoint, {
          protocolVersion: 1,
          method: "stop",
          expectedRevision: 0,
        }),
      );
      expect(error.code).toBeUndefined();
      expect(error.uncertain).toBe(true);
      expect(requests).toBe(1);
    } finally {
      await new Promise<void>((resolve) => peer.close(() => resolve()));
    }
  });

  it("bounds interrupted reads without declaring a live peer absent", async () => {
    const endpoint = socketPath();
    let requests = 0;
    const peer = http.createServer((_req, res) => {
      requests++;
      res.destroy();
    });
    await new Promise<void>((resolve) => peer.listen(endpoint, resolve));
    try {
      const error = await expectFailure(
        workerRequest(endpoint, snapshotRequest),
      );
      expect(error.code).toBeUndefined();
      expect(error.uncertain).toBe(false);
      expect(requests).toBe(2);
    } finally {
      await new Promise<void>((resolve) => peer.close(() => resolve()));
    }
  });

  it("close is bounded with a stalled raw reader and unlinks the socket", async () => {
    const socketPathName = socketPath();
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async () => fixtureSnapshot(),
    });
    const stalled = connect(socketPathName);
    const errors: NodeJS.ErrnoException[] = [];
    stalled.on("error", (error) => errors.push(error));
    const closed = new Promise<void>((resolve) =>
      stalled.once("close", () => resolve()),
    );
    try {
      await once(stalled, "connect");
      stalled.write("POST /rpc HTTP/1.1\r\ncontent-length: 100\r\n\r\n{");
      stalled.resume();

      const started = Date.now();
      await server.close();
      await closed;
      expect(Date.now() - started).toBeLessThan(5_000);
      expect(() => statSync(socketPathName)).toThrow(/ENOENT/);
      // Linux may reset the peer when shutdown discards its partial request.
      for (const error of errors) expect(error.code).toBe("ECONNRESET");
    } finally {
      stalled.destroy();
      await closed;
      await server.close();
    }
  });

  it("refuses new requests after close", async () => {
    const socketPathName = socketPath();
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async () => fixtureSnapshot(),
    });
    await server.close();
    const error = await expectFailure(
      workerRequest(socketPathName, snapshotRequest),
    );
    expect(error.code).toBe("ENOENT");
  });
});

describe("client process hygiene", () => {
  it("a successful client subprocess exits naturally without a leaked timer", async () => {
    if (typeof Bun === "undefined") {
      // The child runs a .ts entry via the Bun runtime executing this test.
      return;
    }
    const socketPathName = socketPath();
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: async () => fixtureSnapshot({ phase: "settled", sequence: 1 }),
    });
    const dir = mkdtempSync(path.join(tmpdir(), "worker-child-"));
    tempDirs.push(dir);
    const transportUrl = fileURLToPath(
      new URL("./localWorkerTransport.ts", import.meta.url),
    );
    const child = `${dir}/child.ts`;
    writeFileSync(
      child,
      `import { workerRequest } from ${JSON.stringify(transportUrl)};\n` +
        `const snapshot = await workerRequest(process.argv[2], { protocolVersion: 1, method: "snapshot" });\n` +
        `if (snapshot.phase !== "settled") throw new Error("bad snapshot");\n` +
        `console.log("ok");\n`,
    );
    try {
      const started = Date.now();
      const code = await new Promise<number | null>((resolve, reject) => {
        const proc = spawn(process.execPath, [child, socketPathName], {
          stdio: ["ignore", "pipe", "pipe"],
        });
        proc.once("error", reject);
        proc.once("exit", (exitCode) => resolve(exitCode));
      });
      expect(code).toBe(0);
      // A leaked timeout would hold the child open for the full default.
      expect(Date.now() - started).toBeLessThan(8_000);
    } finally {
      await server.close();
    }
  });
});

describe("spawn-safe connect classification", () => {
  it("preserves ENOENT for a missing socket", async () => {
    const missing = path.join(socketPath(), "absent.sock");
    const error = await expectFailure(workerRequest(missing, snapshotRequest));
    expect(error.code).toBe("ENOENT");
  });

  it("preserves ECONNREFUSED for a stale socket file", async () => {
    if (typeof Bun === "undefined") return; // child runs under the Bun binary
    const stalePath = socketPath();
    // A dead owner leaves the socket file behind: the child listens, then
    // exits without closing the server (close() would unlink the path).
    const child = spawn(
      process.execPath,
      [
        "-e",
        `const net = require("node:net");
` +
          `net.createServer(() => {}).listen(${JSON.stringify(stalePath)}, () => { console.log("ready"); process.exit(0); });`,
      ],
      { stdio: ["ignore", "ignore", "ignore"] },
    );
    const exited = await new Promise<number | null>((resolve) =>
      child.once("exit", resolve),
    );
    expect(exited).toBe(0);
    expect(() => statSync(stalePath)).not.toThrow(); // stale file remains

    const error = await expectFailure(
      workerRequest(stalePath, snapshotRequest),
    );
    expect(error.code).toBe("ECONNREFUSED");
  });
});

describe("mutation uncertainty", () => {
  it("marks a lost mutation as uncertain and a lost read as plain failure", async () => {
    const socketPathName = socketPath();
    const server = await serveWorkerTransport({
      socketPath: socketPathName,
      handle: () => new Promise<WorkerSnapshot>(() => {}),
    });
    try {
      const mutation = await expectFailure(
        workerRequest(
          socketPathName,
          { protocolVersion: 1, method: "stop", expectedRevision: 0 },
          { timeoutMs: 80 },
        ),
      );
      expect(mutation.uncertain).toBe(true);

      const read = await expectFailure(
        workerRequest(socketPathName, snapshotRequest, { timeoutMs: 80 }),
      );
      expect(read.uncertain).toBe(false);
    } finally {
      await server.close();
    }
  });
});

function aborted(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    if (signal.aborted) reject(new Error("aborted"));
    else
      signal.addEventListener("abort", () => reject(new Error("aborted")), {
        once: true,
      });
  });
}

describe("Bun connect race", () => {
  function failHttpConnect(count: number, code = "FailedToOpenSocket") {
    const original = http.request;
    let failures = 0;
    return vi.spyOn(http, "request").mockImplementation(((
      ...args: Parameters<typeof http.request>
    ) => {
      if (failures++ >= count) return original(...args);
      const request = new EventEmitter() as http.ClientRequest;
      request.destroy = vi.fn(() => request);
      request.end = vi.fn(() => {
        queueMicrotask(() =>
          request.emit(
            "error",
            Object.assign(new Error("Bun connect failed"), {
              code,
            }),
          ),
        );
        return request;
      });
      return request;
    }) as typeof http.request);
  }

  it.each([
    "snapshot",
    "watch",
  ] as const)("retries one %s if the endpoint appears before the diagnostic connects", async (method) => {
    const socket = socketPath();
    const handled: string[] = [];
    const peer = await serveWorkerTransport({
      socketPath: socket,
      handle: async (request) => {
        handled.push(request.method);
        return fixtureSnapshot();
      },
    });
    const spy = failHttpConnect(1);
    try {
      await expect(
        workerRequest(socket, { protocolVersion: 1, method }),
      ).resolves.toEqual(fixtureSnapshot());
      expect(spy).toHaveBeenCalledTimes(2);
      expect(handled).toEqual([method]);
    } finally {
      spy.mockRestore();
      await peer.close();
    }
  });

  it("never retries a mutation when the diagnostic finds a live peer", async () => {
    const socket = socketPath();
    let handled = 0;
    const peer = await serveWorkerTransport({
      socketPath: socket,
      handle: async () => {
        handled++;
        return fixtureSnapshot();
      },
    });
    const spy = failHttpConnect(1);
    try {
      const error = await expectFailure(
        workerRequest(socket, {
          protocolVersion: 1,
          method: "resume",
          expectedAttemptId: "exec_test",
        }),
      );
      expect(error.uncertain).toBe(true);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(handled).toBe(0);
    } finally {
      spy.mockRestore();
      await peer.close();
    }
  });

  it("bounds repeated read connection races to one retry", async () => {
    const socket = socketPath();
    const peer = await serveWorkerTransport({
      socketPath: socket,
      handle: async () => fixtureSnapshot(),
    });
    const spy = failHttpConnect(10);
    try {
      await expect(workerRequest(socket, snapshotRequest)).rejects.toThrow();
      expect(spy).toHaveBeenCalledTimes(2);
    } finally {
      spy.mockRestore();
      await peer.close();
    }
  });

  it.each([
    "EACCES",
    "HPE_INVALID_HEADER_TOKEN",
  ])("does not retry a %s failure", async (code) => {
    const spy = failHttpConnect(10, code);
    const error = await expectFailure(
      workerRequest(socketPath(), snapshotRequest),
    );
    expect(error.code).toBeUndefined();
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
