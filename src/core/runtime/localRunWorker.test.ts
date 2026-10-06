import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LocalRunWorkerOptions } from "./localRunWorker";
import type { LocalWorkerRequest, WorkerSnapshot } from "./localWorkerProtocol";
import { RecordedRunSpecSchema } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

const transport = vi.hoisted(() => ({
  handle: undefined as
    | ((
        request: LocalWorkerRequest,
        signal: AbortSignal,
      ) => Promise<WorkerSnapshot>)
    | undefined,
  close: vi.fn(async () => {}),
}));
vi.mock("./localWorkerTransport", () => ({
  serveWorkerTransport: async (input: { handle: typeof transport.handle }) => {
    transport.handle = input.handle;
    return { close: transport.close };
  },
}));
vi.mock("./localWorkerEndpoint", () => ({
  resolveWorkerEndpoint: async (database: string) => ({
    socketPath: `${database}.socket`,
    logPath: `${database}.log`,
    lockDatabasePath: `${database}.hosts`,
  }),
}));

const { serveLocalRunWorker } = await import("./localRunWorker");
const cleanup: Array<() => Promise<unknown>> = [];

afterEach(async () => {
  for (const dispose of cleanup.reverse()) await dispose();
  cleanup.length = 0;
  transport.handle = undefined;
  vi.clearAllMocks();
});

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "apex-host-"));
  cleanup.push(() => rm(root, { recursive: true, force: true }));
  const databasePath = join(root, "runs.sqlite");
  const store = await openSqliteRunStore(databasePath);
  cleanup.push(async () => store.close());
  const spec = RecordedRunSpecSchema.parse({
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_worker_state",
    prompt: "Inspect a local file.",
    target: "local",
    model: "claude-haiku-4-5",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: root },
    scope: { version: 1, strictScope: true },
  });
  return { store, spec, databasePath };
}

async function send(
  request: LocalWorkerRequest,
  signal = new AbortController().signal,
) {
  if (!transport.handle) throw new Error("Worker transport is not ready");
  return transport.handle(request, signal);
}

describe("local worker invocation ownership", () => {
  it("disconnects observers without cancelling execution or launching duplicate work", async () => {
    const { spec, databasePath } = await setup();
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let executionSignal: AbortSignal | undefined;
    const execute = vi.fn(
      async ({
        store,
        signal,
      }: Parameters<LocalRunWorkerOptions["execute"]>[0]) => {
        executionSignal = signal;
        const { record } = await store.admit(spec);
        const lock = await store.acquireExecutionLock(spec.runId);
        try {
          await store.initializeControl(spec.runId, record.attemptId);
          await store.transition(spec.runId, record.attemptId, "running");
          await held;
          await store.transition(spec.runId, record.attemptId, "completed");
        } finally {
          lock.release();
        }
      },
    );
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      settledTimeoutMs: 10,
    });
    cleanup.push(async () => {
      release();
      await running;
    });
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    const request = { protocolVersion: 1, method: "start", spec } as const;
    const client = new AbortController();
    await send(request, client.signal);
    await vi.waitFor(() => expect(executionSignal).toBeDefined());
    await send(request);
    client.abort();
    await expect(
      send({ protocolVersion: 1, method: "watch" }, client.signal),
    ).rejects.toThrow();
    expect(executionSignal?.aborted).toBe(false);
    expect(execute).toHaveBeenCalledTimes(1);
    await expect(
      send({ ...request, spec: { ...spec, prompt: "Changed" } }),
    ).rejects.toThrow("different specification");
    release();
    await running;
    expect(transport.close).toHaveBeenCalledTimes(1);
  });

  it("returns an existing admission without executing or treating start as resume", async () => {
    const { spec, store, databasePath } = await setup();
    const admitted = await store.admit(spec);
    const execute = vi.fn();
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      settledTimeoutMs: 10,
    });
    cleanup.push(() => running);
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    const value = await send({ protocolVersion: 1, method: "start", spec });
    expect(value.phase).toBe("settled");
    expect(value.observation.record).toEqual(admitted.record);
    expect(execute).not.toHaveBeenCalled();
    await running;
  });

  it("expires an unused host without creating a run", async () => {
    const { spec, store, databasePath } = await setup();
    const execute = vi.fn();
    transport.close.mockImplementationOnce(async () => {
      await expect(
        send({ protocolVersion: 1, method: "start", spec }),
      ).rejects.toThrow("Worker is shutting down");
    });
    await serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      idleTimeoutMs: 10,
    });
    expect(execute).not.toHaveBeenCalled();
    expect(await store.get(spec.runId)).toBeUndefined();
    expect(transport.close).toHaveBeenCalledTimes(1);
  });
});
