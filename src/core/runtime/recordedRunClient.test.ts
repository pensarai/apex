import { setTimeout as delay } from "node:timers/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { WorkerSnapshot } from "./localWorkerProtocol";
import type { RecordedApproval, RunControlRecord } from "./runControlStore";
import type { RunContextSnapshot, RunObservation } from "./runObservation";
import {
  RecordedRunSpecSchema,
  type RunRecord,
  RunRecordSchema,
} from "./runStore";

const openSqliteRunStore = vi.hoisted(() => vi.fn());
const resolveWorkerEndpoint = vi.hoisted(() => vi.fn());
const workerRequest = vi.hoisted(() => vi.fn());
const launchLocalWorker = vi.hoisted(() => vi.fn());

vi.mock("./sqliteRunStore", () => ({ openSqliteRunStore }));
vi.mock("./localWorkerEndpoint", () => ({ resolveWorkerEndpoint }));
vi.mock("./localWorkerTransport", () => ({ workerRequest }));
vi.mock("./launchLocalWorker", () => ({ launchLocalWorker }));

const { openRecordedRunClient } = await import("./recordedRunClient");

import type { RecordedRunView } from "./recordedRunClient";

const RUN_ID = "run_c5_client";
const ATTEMPT_ID = "exec_00000000-0000-4000-8000-000000000001";
const DATABASE = "/tmp/c5-runtime/runs.sqlite";
const ENDPOINT = {
  socketPath: "/tmp/pensar-worker-501/c5.sock",
  logPath: "/tmp/pensar-worker-501/c5.log",
  lockDatabasePath: "/tmp/pensar-worker-501/c5.host.sqlite",
};

function validRecord(status: RunRecord["status"]): RunRecord {
  const spec = RecordedRunSpecSchema.parse({
    schemaVersion: 1,
    configVersion: 1,
    runId: RUN_ID,
    prompt: "test the target",
    target: "https://example.com",
    model: "claude-sonnet-4-6",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: "/tmp/target" },
    scope: { version: 1, strictScope: true },
  });
  return RunRecordSchema.parse({
    schemaVersion: 1,
    spec,
    sessionId: "ses_c5client0000000000000000",
    attemptId: ATTEMPT_ID,
    runtimeVersion: "0.0.0-test",
    status,
    admittedAt: "2026-10-06T00:00:00.000Z",
    updatedAt: "2026-10-06T00:00:00.000Z",
  });
}

function controlRecord(revision = 1): RunControlRecord {
  return {
    schemaVersion: 1,
    runId: RUN_ID,
    executionAttemptId: ATTEMPT_ID,
    intent: "run",
    revision,
    updatedAt: "2026-10-06T00:00:00.000Z",
  };
}

function approvalRecord(): RecordedApproval {
  return {
    schemaVersion: 1,
    approvalId: "apr_1",
    runId: RUN_ID,
    executionAttemptId: ATTEMPT_ID,
    toolCallId: "tc_1",
    toolName: "http_request",
    input: { method: "GET" },
    specDigest: "0".repeat(64),
    context: { epoch: 1, revision: 1 },
    state: "approved",
    createdAt: "2026-10-06T00:00:00.000Z",
    decidedAt: "2026-10-06T00:00:01.000Z",
  };
}

function observation(overrides: Partial<RunObservation> = {}): RunObservation {
  return {
    record: validRecord("running"),
    context: null,
    control: controlRecord(),
    approvals: [],
    ...overrides,
  };
}

function snapshot(
  overrides: Partial<WorkerSnapshot> & { observation: RunObservation },
): WorkerSnapshot {
  return {
    protocolVersion: 1,
    workerId: "worker-1",
    runId: RUN_ID,
    phase: "executing",
    sequence: 1,
    ...overrides,
  };
}

function absentError(code: "ENOENT" | "ECONNREFUSED" = "ECONNREFUSED") {
  return Object.assign(new Error(`connect ${code}`), { code });
}

function makeStore(observeImpl?: (runId: string) => Promise<RunObservation>) {
  const store = {
    observe: vi.fn(observeImpl ?? (async () => observation())),
    list: vi.fn(async () => [validRecord("running")]),
    requestControl: vi.fn(async () => controlRecord(2)),
    resolveApproval: vi.fn(async () => approvalRecord()),
    close: vi.fn(),
  };
  openSqliteRunStore.mockResolvedValue(store);
  return store;
}

async function makeClient(store?: ReturnType<typeof makeStore>) {
  const opened = store ?? makeStore();
  resolveWorkerEndpoint.mockResolvedValue(ENDPOINT);
  const client = await openRecordedRunClient(DATABASE);
  return { client, store: opened };
}

function asView(
  result: IteratorResult<RecordedRunView, void>,
): RecordedRunView {
  expect(result.done).not.toBe(true);
  if (result.done) throw new Error("expected a yielded view");
  return result.value;
}

function workerOf(view: RecordedRunView): WorkerSnapshot {
  expect(view.worker).not.toBeNull();
  if (!view.worker) throw new Error("expected a live worker view");
  return view.worker;
}

beforeEach(() => {
  openSqliteRunStore.mockReset();
  resolveWorkerEndpoint.mockReset();
  workerRequest.mockReset();
  launchLocalWorker.mockReset();
});

describe("openRecordedRunClient", () => {
  it("resolves the same canonical database default as the store", async () => {
    const previous = process.env.PENSAR_DATA_DIR;
    try {
      process.env.PENSAR_DATA_DIR = "/tmp/c5-data-dir";
      makeStore();
      const client = await openRecordedRunClient();
      expect(client.databasePath).toBe("/tmp/c5-data-dir/runtime/runs.sqlite");
      await client.close();
    } finally {
      if (previous === undefined) delete process.env.PENSAR_DATA_DIR;
      else process.env.PENSAR_DATA_DIR = previous;
    }
  });

  it("resolves an explicit relative path against the process cwd", async () => {
    makeStore();
    const client = await openRecordedRunClient("nested/runs.sqlite");
    expect(client.databasePath.startsWith("/")).toBe(true);
    expect(client.databasePath.endsWith("nested/runs.sqlite")).toBe(true);
    await client.close();
  });

  it("lists saved records from the store", async () => {
    const { client } = await makeClient();
    expect(await client.list()).toEqual([validRecord("running")]);
    await client.close();
  });
});

describe("observe", () => {
  it("reports offline with the atomic saved snapshot; saved running is never presented as live", async () => {
    const { client, store } = await makeClient();
    workerRequest.mockRejectedValue(absentError());

    const view = await client.observe(RUN_ID);

    expect(view.connection).toBe("offline");
    expect(view.worker).toBeNull();
    expect(view.observation.record?.status).toBe("running");
    expect(view.observation.record?.spec.runId).toBe(RUN_ID);
    expect(store.observe).toHaveBeenCalledWith(RUN_ID);
    await client.close();
  });

  it("reports error with the saved snapshot for a malformed peer", async () => {
    const { client } = await makeClient();
    workerRequest.mockRejectedValue(
      new Error("worker responded with protocolVersion 99"),
    );

    const view = await client.observe(RUN_ID);

    expect(view.connection).toBe("error");
    expect(view.error).toContain("protocolVersion 99");
    expect(view.worker).toBeNull();
    expect(view.observation.record?.status).toBe("running");
    await client.close();
  });

  it("errors explicitly for an unknown run with no saved or live record", async () => {
    const store = makeStore(async () => observation({ record: null }));
    const { client } = await makeClient(store);
    workerRequest.mockRejectedValue(absentError("ENOENT"));

    await expect(client.observe("run_unknown")).rejects.toThrow(
      "Run not found: run_unknown",
    );
    await client.close();
  });

  it("uses the live worker's observation when connected", async () => {
    const { client } = await makeClient();
    const live = snapshot({
      phase: "executing",
      sequence: 4,
      observation: observation({ record: validRecord("paused") }),
    });
    workerRequest.mockResolvedValue(live);

    const view = await client.observe(RUN_ID);

    expect(view.connection).toBe("connected");
    expect(view.worker).toBe(live);
    expect(view.observation.record?.status).toBe("paused");
    await client.close();
  });

  it("never exposes a snapshot belonging to another run", async () => {
    const { client } = await makeClient();
    workerRequest.mockResolvedValue(
      snapshot({ runId: "run_other", observation: observation() }),
    );

    const view = await client.observe(RUN_ID);

    expect(view.connection).toBe("error");
    expect(view.worker).toBeNull();
    expect(view.error).toContain("serves another run");
    await client.close();
  });
});

describe("watch", () => {
  it("coalesces unchanged watch replies and yields on the real change", async () => {
    const { client } = await makeClient();
    const first = snapshot({ sequence: 1, observation: observation() });
    const changed = snapshot({ sequence: 2, observation: observation() });
    let watchCalls = 0;
    workerRequest.mockImplementation(
      async (_path: string, req: { method: string }) => {
        if (req.method === "snapshot") return first;
        watchCalls += 1;
        return watchCalls <= 2 ? first : changed;
      },
    );

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    expect(workerOf(asView(await gen.next())).sequence).toBe(1);

    // Two unchanged rounds happen only as polling time passes; the changed
    // one is the only additional yield.
    const second = gen.next();
    expect(workerOf(asView(await second)).sequence).toBe(2);
    expect(watchCalls).toBeGreaterThanOrEqual(3);

    controller.abort();
    expect((await gen.next()).done).toBe(true);
    await client.close();
  });

  it("surfaces committed context changes while offline even with status and control unchanged", async () => {
    const baseRecord = validRecord("running");
    const control: RunControlRecord = {
      schemaVersion: 1,
      runId: RUN_ID,
      executionAttemptId: ATTEMPT_ID,
      intent: "run",
      revision: 1,
      updatedAt: "2026-10-06T00:00:00.000Z",
    };
    let contextRevision = 5;
    const context = (): RunContextSnapshot => ({
      epoch: 2,
      revision: contextRevision,
      messages: [{ role: "user", content: "probe" }],
      system: null,
    });
    const store = makeStore(async () =>
      observation({ record: baseRecord, control, context: context() }),
    );
    const { client } = await makeClient(store);
    workerRequest.mockRejectedValue(absentError());

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    const first = asView(await gen.next());
    expect(first.connection).toBe("offline");
    expect(first.observation.context?.revision).toBe(5);

    // A foreground writer appends context; nothing else in the saved view
    // changes, so only the context revision can carry the update.
    contextRevision = 6;
    const second = gen.next();
    const view = asView(await second);
    expect(view.connection).toBe("offline");
    expect(view.observation.context?.revision).toBe(6);
    expect(view.observation.record?.status).toBe("running");
    expect(view.observation.control?.revision).toBe(1);

    controller.abort();
    expect((await gen.next()).done).toBe(true);
    await client.close();
  });

  it("bounds fast unchanged watch replies instead of spinning on an immediate peer", async () => {
    const { client } = await makeClient();
    const same = snapshot({ sequence: 7, observation: observation() });
    const requestTimes: number[] = [];
    workerRequest.mockImplementation(async () => {
      requestTimes.push(Date.now());
      if (requestTimes.length > 20)
        throw new Error("Immediate peer is spinning");
      return same;
    });
    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    asView(await gen.next());
    const pending = gen.next();
    try {
      await vi.waitFor(
        () => expect(requestTimes.length).toBeGreaterThanOrEqual(4),
        { timeout: 2_000 },
      );
      for (let index = 1; index < requestTimes.length; index++) {
        expect(
          requestTimes[index] - requestTimes[index - 1],
        ).toBeGreaterThanOrEqual(175);
      }
    } finally {
      controller.abort();
      expect((await pending).done).toBe(true);
      await client.close();
    }
  });

  it("delays before re-probing while offline and surfaces control revisions without claiming liveness", async () => {
    let revision = 1;
    const store = makeStore(async () =>
      observation({
        control: {
          schemaVersion: 1,
          runId: RUN_ID,
          executionAttemptId: ATTEMPT_ID,
          intent: "run",
          revision,
          updatedAt: "2026-10-06T00:00:00.000Z",
        },
      }),
    );
    const { client } = await makeClient(store);
    workerRequest.mockRejectedValue(absentError());

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    const first = asView(await gen.next());
    expect(first.connection).toBe("offline");
    expect(first.observation.control?.revision).toBe(1);

    revision = 2;
    const second = gen.next();
    const raced = await Promise.race([
      second.then(() => "settled"),
      delay(50).then(() => "pending"),
    ]);
    expect(raced).toBe("pending");
    const view = asView(await second);
    expect(view.connection).toBe("offline");
    expect(view.observation.control?.revision).toBe(2);
    controller.abort();
    await client.close();
  });

  it("delays after a settled host instead of spinning until it retires to offline", async () => {
    const { client } = await makeClient();
    let snapshotCalls = 0;
    workerRequest.mockImplementation(
      async (_path: string, req: { method: string }) => {
        if (req.method !== "snapshot") {
          throw new Error("unexpected watch call");
        }
        snapshotCalls += 1;
        return snapshotCalls === 1
          ? snapshot({ phase: "settled", observation: observation() })
          : Promise.reject(absentError());
      },
    );

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    expect(workerOf(asView(await gen.next())).phase).toBe("settled");

    const second = gen.next();
    const raced = await Promise.race([
      second.then(() => "settled"),
      delay(50).then(() => "pending"),
    ]);
    expect(raced).toBe("pending");
    expect(asView(await second).connection).toBe("offline");
    controller.abort();
    await client.close();
  });

  it("replaces the view when the worker identity changes", async () => {
    const { client } = await makeClient();
    let workerId = "worker-1";
    workerRequest.mockImplementation(
      async (_path: string, req: { method: string }) => {
        if (req.method === "snapshot") {
          return snapshot({ workerId, observation: observation() });
        }
        workerId = "worker-2";
        return snapshot({ workerId, sequence: 1, observation: observation() });
      },
    );

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    expect(workerOf(asView(await gen.next())).workerId).toBe("worker-1");
    const second = gen.next();
    expect(workerOf(asView(await second)).workerId).toBe("worker-2");
    controller.abort();
    expect((await gen.next()).done).toBe(true);
    await client.close();
  });

  it("aborts an in-flight observation without issuing any control or stop", async () => {
    const { client, store } = await makeClient();
    const first = snapshot({ sequence: 1, observation: observation() });
    workerRequest.mockImplementation(
      (
        _path: string,
        req: { method: string },
        opts: { signal?: AbortSignal },
      ) => {
        if (req.method === "snapshot") return Promise.resolve(first);
        return new Promise((_resolve, reject) => {
          const fail = () => reject(new Error("cancelled"));
          if (opts.signal?.aborted) {
            fail();
            return;
          }
          opts.signal?.addEventListener("abort", fail, { once: true });
        });
      },
    );

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    asView(await gen.next());
    const pending = gen.next();
    await vi.waitFor(() => expect(workerRequest).toHaveBeenCalledTimes(2));
    controller.abort();
    expect((await pending).done).toBe(true);
    expect(store.requestControl).not.toHaveBeenCalled();
    await client.close();
  });

  it("aborts during the offline delay and ends the stream", async () => {
    const { client } = await makeClient();
    workerRequest.mockRejectedValue(absentError());

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    asView(await gen.next());
    const pending = gen.next();
    controller.abort();
    expect((await pending).done).toBe(true);
    await client.close();
  });
});

describe("start and resume", () => {
  const SPEC = {
    schemaVersion: 1,
    configVersion: 1,
    runId: RUN_ID,
    prompt: "test the target",
    target: "https://example.com",
    model: "claude-sonnet-4-6",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: "/tmp/target" },
    scope: { version: 1, strictScope: true },
  };
  const EXECUTABLE = { command: "pensar", args: ["/repo/build/cli.js"] };

  it("start launches the worker with the normalized spec and dispatches once", async () => {
    const { client } = await makeClient();
    launchLocalWorker.mockResolvedValue({
      socketPath: ENDPOINT.socketPath,
      logPath: ENDPOINT.logPath,
    });
    const started = snapshot({ observation: observation() });
    workerRequest.mockResolvedValue(started);

    const launch = await client.start(SPEC, EXECUTABLE);

    expect(launchLocalWorker).toHaveBeenCalledWith({
      runId: RUN_ID,
      databasePath: DATABASE,
      executable: EXECUTABLE,
    });
    expect(workerRequest).toHaveBeenCalledTimes(1);
    expect(workerRequest.mock.calls[0][1]).toEqual({
      protocolVersion: 1,
      method: "start",
      spec: expect.objectContaining({ runId: RUN_ID, credentialRefs: [] }),
    });
    expect(launch.socketPath).toBe(ENDPOINT.socketPath);
    expect(launch.snapshot).toBe(started);
    await client.close();
  });

  it("start never retries an uncertain acknowledgement", async () => {
    const { client } = await makeClient();
    launchLocalWorker.mockResolvedValue({
      socketPath: ENDPOINT.socketPath,
      logPath: ENDPOINT.logPath,
    });
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connection lost mid-request"), {
        uncertain: true,
      }),
    );

    await expect(client.start(SPEC, EXECUTABLE)).rejects.toThrow(
      "connection lost mid-request",
    );
    expect(workerRequest).toHaveBeenCalledTimes(1);
    await client.close();
  });

  it("resume binds the observed attempt id and dispatches once", async () => {
    const { client } = await makeClient();
    launchLocalWorker.mockResolvedValue({
      socketPath: ENDPOINT.socketPath,
      logPath: ENDPOINT.logPath,
    });
    workerRequest.mockResolvedValue(snapshot({ observation: observation() }));

    await client.resume(RUN_ID, ATTEMPT_ID, EXECUTABLE);

    expect(launchLocalWorker).toHaveBeenCalledWith({
      runId: RUN_ID,
      databasePath: DATABASE,
      executable: EXECUTABLE,
    });
    expect(workerRequest).toHaveBeenCalledWith(ENDPOINT.socketPath, {
      protocolVersion: 1,
      method: "resume",
      expectedAttemptId: ATTEMPT_ID,
    });
    await client.close();
  });

  it("resume never retries an uncertain acknowledgement", async () => {
    const { client } = await makeClient();
    launchLocalWorker.mockResolvedValue({
      socketPath: ENDPOINT.socketPath,
      logPath: ENDPOINT.logPath,
    });
    workerRequest.mockRejectedValue(
      Object.assign(new Error("connection lost mid-request"), {
        uncertain: true,
      }),
    );

    await expect(client.resume(RUN_ID, ATTEMPT_ID, EXECUTABLE)).rejects.toThrow(
      "connection lost mid-request",
    );
    expect(workerRequest).toHaveBeenCalledTimes(1);
    await client.close();
  });
});

describe("durable controls", () => {
  it("requestControl uses the revision shown to the operator, not a fresh read", async () => {
    const { client, store } = await makeClient();

    await client.requestControl(RUN_ID, "pause", 7);

    expect(store.requestControl).toHaveBeenCalledWith(RUN_ID, "pause", 7);
    await client.close();
  });

  it("resolveApproval binds one decision to one approval id", async () => {
    const { client, store } = await makeClient();

    await client.resolveApproval(RUN_ID, "apr_1", "denied");

    expect(store.resolveApproval).toHaveBeenCalledWith(
      RUN_ID,
      "apr_1",
      "denied",
    );
    await client.close();
  });
});

describe("close", () => {
  it("aborts a pending read before closing the store", async () => {
    const events: string[] = [];
    const store = makeStore(async () => observation());
    store.close.mockImplementation(() => {
      events.push("store-closed");
    });
    const { client } = await makeClient(store);
    const first = snapshot({ sequence: 1, observation: observation() });
    workerRequest.mockImplementation(
      (
        _path: string,
        req: { method: string },
        opts: { signal?: AbortSignal },
      ) => {
        if (req.method === "snapshot") return Promise.resolve(first);
        return new Promise((_resolve, reject) => {
          events.push("read-started");
          const fail = () => {
            events.push("read-aborted");
            reject(new Error("cancelled"));
          };
          if (opts.signal?.aborted) {
            fail();
            return;
          }
          opts.signal?.addEventListener("abort", fail, { once: true });
        });
      },
    );

    const controller = new AbortController();
    const gen = client.watch(RUN_ID, controller.signal);
    asView(await gen.next());
    const pending = gen.next();
    await vi.waitFor(() => expect(events).toContain("read-started"));

    await client.close();
    expect((await pending).done).toBe(true);
    expect(events).toEqual(["read-started", "read-aborted", "store-closed"]);
    controller.abort();
  });

  it("is idempotent, closes the store once, and never stops a worker", async () => {
    const { client, store } = await makeClient();

    await client.close();
    await client.close();

    expect(store.close).toHaveBeenCalledTimes(1);
    expect(launchLocalWorker).not.toHaveBeenCalled();
    await expect(client.observe(RUN_ID)).rejects.toThrow(/closed/);
  });
});
