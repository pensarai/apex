import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LocalRunWorkerOptions } from "./localRunWorker";
import type { LocalWorkerRequest, WorkerSnapshot } from "./localWorkerProtocol";
import { LocalWorkerRequestRejectedError } from "./localWorkerTransport";
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
const storeOverride = vi.hoisted(() => ({
  wrap: undefined as
    | ((store: unknown) => Promise<unknown> | undefined)
    | undefined,
}));
vi.mock("./localWorkerTransport", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
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
vi.mock("./sqliteRunStore", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    openSqliteRunStore: async (databasePath: string) => {
      const store = await (
        actual.openSqliteRunStore as typeof openSqliteRunStore
      )(databasePath);
      return storeOverride.wrap ? await storeOverride.wrap(store) : store;
    },
  };
});

const { serveLocalRunWorker } = await import("./localRunWorker");
const cleanup: Array<() => Promise<unknown>> = [];

afterEach(async () => {
  for (const dispose of cleanup.reverse()) await dispose();
  cleanup.length = 0;
  transport.handle = undefined;
  storeOverride.wrap = undefined;
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

async function expectRejection(
  request: LocalWorkerRequest,
  pattern: RegExp,
): Promise<void> {
  const cause = await send(request).then(
    () => {
      throw new Error("expected the request to be rejected");
    },
    (rejection) => rejection,
  );
  expect(cause).toBeInstanceOf(LocalWorkerRequestRejectedError);
  expect(cause.message).toMatch(pattern);
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

describe("no-start ownership", () => {
  it("reports failure when a concurrent client wins admission and this worker never starts", async () => {
    const { spec, store, databasePath } = await setup();
    // The foreground client wins admit while our execute is in flight;
    // the resolved value is runRecordedAgent's duplicate-admission shape.
    const execute = vi.fn(async () => {
      const foreground = await store.admit(spec);
      await store.initializeControl(spec.runId, foreground.record.attemptId);
      await store.transition(
        spec.runId,
        foreground.record.attemptId,
        "running",
      );
      return { started: false, record: await store.get(spec.runId) };
    });
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      settledTimeoutMs: 1_000,
    });
    cleanup.push(() => running);
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    const executing = await send({ protocolVersion: 1, method: "start", spec });
    expect(executing.phase).toBe("executing");
    const settled = await vi.waitFor(async () => {
      const value = await send({ protocolVersion: 1, method: "snapshot" });
      expect(value.phase).toBe("settled");
      return value;
    });
    expect(settled.error?.message).toMatch(/already admitted/i);
    expect(settled.observation.record?.status).toBe("running");
    expect(execute).toHaveBeenCalledTimes(1);
    await running;
  });

  it("settles cleanly when a pre-aborted start returns started:false with a cancelled record", async () => {
    const { spec, store, databasePath } = await setup();
    const execute = vi.fn(async () => {
      const foreground = await store.admit(spec);
      await store.initializeControl(spec.runId, foreground.record.attemptId);
      await store.requestControl(spec.runId, "stop", 0);
      const record = await store.transition(
        spec.runId,
        foreground.record.attemptId,
        "cancelled",
      );
      return { started: false, record };
    });
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      settledTimeoutMs: 1_000,
    });
    cleanup.push(() => running);
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    await send({ protocolVersion: 1, method: "start", spec });
    const settled = await vi.waitFor(async () => {
      const value = await send({ protocolVersion: 1, method: "snapshot" });
      expect(value.phase).toBe("settled");
      return value;
    });
    expect(settled.error).toBeUndefined();
    expect(settled.observation.record?.status).toBe("cancelled");
    await running;
  });

  it("settles cleanly when a pause pre-empts the start with started:false and a paused record", async () => {
    const { spec, store, databasePath } = await setup();
    const execute = vi.fn(async () => {
      const foreground = await store.admit(spec);
      await store.initializeControl(spec.runId, foreground.record.attemptId);
      await store.requestControl(spec.runId, "pause", 0);
      const record = await store.transition(
        spec.runId,
        foreground.record.attemptId,
        "paused",
      );
      return { started: false, record };
    });
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      settledTimeoutMs: 1_000,
    });
    cleanup.push(() => running);
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    await send({ protocolVersion: 1, method: "start", spec });
    const settled = await vi.waitFor(async () => {
      const value = await send({ protocolVersion: 1, method: "snapshot" });
      expect(value.phase).toBe("settled");
      return value;
    });
    expect(settled.error).toBeUndefined();
    expect(settled.observation.record?.status).toBe("paused");
    await running;
  });

  it("surfaces a post-execute read failure as a snapshot error, not an unhandled rejection", async () => {
    const { spec, databasePath } = await setup();
    storeOverride.wrap = async (store) => {
      const real = store as Awaited<ReturnType<typeof openSqliteRunStore>>;
      let gets = 0;
      return {
        ...real,
        get: async (id: string) => {
          gets += 1;
          // The start pre-check reads first; the fulfillment read is second.
          if (gets === 2) {
            throw new Error("simulated post-execute read failure");
          }
          return real.get(id);
        },
      };
    };
    const execute = vi.fn(async () => ({ started: false }));
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      settledTimeoutMs: 1_000,
    });
    cleanup.push(() => running);
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    await send({ protocolVersion: 1, method: "start", spec });
    const settled = await vi.waitFor(async () => {
      const value = await send({ protocolVersion: 1, method: "snapshot" });
      expect(value.phase).toBe("settled");
      return value;
    });
    expect(settled.error?.message).toBe("simulated post-execute read failure");
    await running;
  });

  it("answers pure pre-mutation validation with typed definite rejections", async () => {
    const { spec, store, databasePath } = await setup();
    await store.admit(spec);
    const execute = vi.fn();
    // A generous idle timeout keeps the host open for every branch; the
    // idempotent start below ends it via the short settled timeout.
    const running = serveLocalRunWorker({
      runId: spec.runId,
      databasePath,
      execute,
      idleTimeoutMs: 60_000,
      settledTimeoutMs: 10,
    });
    cleanup.push(() => running);
    await vi.waitFor(() => expect(transport.handle).toBeDefined());
    await expectRejection(
      {
        protocolVersion: 1,
        method: "start",
        spec: { ...spec, prompt: "Changed" },
      },
      /different specification/,
    );
    await expectRejection(
      {
        protocolVersion: 1,
        method: "start",
        spec: { ...spec, prompt: "" },
      },
      /Invalid run spec/,
    );
    await expectRejection(
      {
        protocolVersion: 1,
        method: "resume",
        expectedAttemptId: "exec_00000000-0000-4000-8000-000000000000",
      },
      /Recovery attempt changed/,
    );
    expect(execute).not.toHaveBeenCalled();
    const settled = await send({ protocolVersion: 1, method: "start", spec });
    expect(settled.phase).toBe("settled");
    expect(settled.observation.record?.status).toBe("admitted");
    await running;
  });
});
