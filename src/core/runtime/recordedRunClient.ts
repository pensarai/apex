import { setTimeout as delay } from "node:timers/promises";
import type { WorkerExecutable } from "./launchLocalWorker";
import { launchLocalWorker } from "./launchLocalWorker";
import { resolveWorkerEndpoint } from "./localWorkerEndpoint";
import type { WorkerSnapshot } from "./localWorkerProtocol";
import { workerRequest } from "./localWorkerTransport";
import type { RecordedApproval, RunControlRecord } from "./runControlStore";
import type { RunObservation } from "./runObservation";
import { RecordedRunSpecSchema, type RunRecord } from "./runStore";
import { resolveRunDatabasePath } from "./runStorePath";
import { openSqliteRunStore } from "./sqliteRunStore";

export type RecordedRunConnection = "connected" | "offline" | "error";

export interface RecordedRunView {
  runId: string;
  /** Atomic committed state; the worker's read when connected. */
  observation: RunObservation;
  worker: WorkerSnapshot | null;
  connection: RecordedRunConnection;
  error?: string;
}

export interface RecordedRunLaunch {
  socketPath: string;
  logPath: string;
  snapshot: WorkerSnapshot;
}

export interface RecordedRunClient {
  databasePath: string;
  list(): Promise<RunRecord[]>;
  observe(runId: string, signal?: AbortSignal): Promise<RecordedRunView>;
  /** Yields the current view, then changed views; returns when aborted. */
  watch(
    runId: string,
    signal: AbortSignal,
  ): AsyncGenerator<RecordedRunView, void, void>;
  start(
    spec: unknown,
    executable: WorkerExecutable,
  ): Promise<RecordedRunLaunch>;
  resume(
    runId: string,
    expectedAttemptId: string,
    executable: WorkerExecutable,
  ): Promise<RecordedRunLaunch>;
  requestControl(
    runId: string,
    intent: "pause" | "stop",
    expectedRevision: number,
  ): Promise<RunControlRecord>;
  resolveApproval(
    runId: string,
    approvalId: string,
    decision: "approved" | "denied",
  ): Promise<RecordedApproval>;
  /** Aborts and drains owned reads before closing the store; never stops a worker. */
  close(): Promise<void>;
}

function isEndpointAbsent(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === "ENOENT" || code === "ECONNREFUSED";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const CONNECT_TIMEOUT_MS = 2_000;
// The worker's watch caps at ~1s server-side; give it room, then re-evaluate.
const WATCH_TIMEOUT_MS = 5_000;
const RETRY_DELAY_MS = 1_000;

/** Observation never launches a worker; start/resume are explicit one-shot requests. */
export async function openRecordedRunClient(
  databasePath?: string,
): Promise<RecordedRunClient> {
  const resolved = resolveRunDatabasePath(databasePath);
  const store = await openSqliteRunStore(resolved);
  let closed = false;
  let closing: Promise<void> | undefined;
  const lifetime = new AbortController();
  const reads = new Set<Promise<unknown>>();

  const assertOpen = () => {
    if (closed) throw new Error("Recorded run client is closed");
  };

  const read = async <T>(
    operation: (signal: AbortSignal) => Promise<T>,
    external?: AbortSignal,
  ): Promise<T> => {
    assertOpen();
    const signal = external
      ? AbortSignal.any([external, lifetime.signal])
      : lifetime.signal;
    signal.throwIfAborted();
    const pending = operation(signal);
    reads.add(pending);
    try {
      return await pending;
    } finally {
      reads.delete(pending);
    }
  };

  const probe = async (
    runId: string,
    signal: AbortSignal,
    cursor?: { workerId: string; sequence: number },
  ): Promise<WorkerSnapshot> => {
    const endpoint = await resolveWorkerEndpoint(resolved, runId);
    signal.throwIfAborted();
    const snapshot = await workerRequest(
      endpoint.socketPath,
      cursor
        ? { protocolVersion: 1, method: "watch", cursor }
        : { protocolVersion: 1, method: "snapshot" },
      { signal, timeoutMs: cursor ? WATCH_TIMEOUT_MS : CONNECT_TIMEOUT_MS },
    );
    signal.throwIfAborted();
    if (
      snapshot.runId !== runId ||
      (snapshot.observation.record &&
        snapshot.observation.record.spec.runId !== runId)
    ) {
      throw new Error("The live worker serves another run");
    }
    return snapshot;
  };

  const savedView = async (
    runId: string,
    connection: "offline" | "error",
    error?: string,
  ): Promise<RecordedRunView> => {
    const observation = await store.observe(runId);
    return {
      runId,
      observation,
      worker: null,
      connection,
      ...(error !== undefined ? { error } : {}),
    };
  };

  const viewFromSnapshot = (
    runId: string,
    snapshot: WorkerSnapshot,
  ): RecordedRunView => ({
    runId,
    observation: snapshot.observation,
    worker: snapshot,
    connection: "connected",
  });

  const classify = async (
    runId: string,
    cause: unknown,
  ): Promise<RecordedRunView> => {
    if (isEndpointAbsent(cause)) {
      const view = await savedView(runId, "offline");
      if (view.observation.record === null) {
        throw new Error(`Run not found: ${runId}`);
      }
      return view;
    }
    return savedView(runId, "error", errorMessage(cause));
  };

  const readView = async (
    runId: string,
    signal: AbortSignal,
    cursor?: { workerId: string; sequence: number },
  ): Promise<RecordedRunView> => {
    try {
      return viewFromSnapshot(runId, await probe(runId, signal, cursor));
    } catch (error) {
      if (signal.aborted) throw error;
      return classify(runId, error);
    }
  };

  const observe = (runId: string, signal?: AbortSignal) =>
    read((ownedSignal) => readView(runId, ownedSignal), signal);

  const viewKey = (view: RecordedRunView): string =>
    view.worker
      ? `${view.worker.workerId}:${view.worker.sequence}`
      : JSON.stringify(view);

  async function* watch(
    runId: string,
    external: AbortSignal,
  ): AsyncGenerator<RecordedRunView, void, void> {
    assertOpen();
    const signal = AbortSignal.any([external, lifetime.signal]);
    let previous: string | undefined;
    let cursor: { workerId: string; sequence: number } | undefined;
    while (!signal.aborted) {
      const began = Date.now();
      try {
        const view = await read(
          (ownedSignal) => readView(runId, ownedSignal, cursor),
          signal,
        );
        cursor =
          view.worker && view.worker.phase !== "settled"
            ? { workerId: view.worker.workerId, sequence: view.worker.sequence }
            : undefined;
        const next = viewKey(view);
        if (next !== previous) {
          previous = next;
          yield view;
        }
        // Also bound peers that answer unchanged watches without long-polling.
        const interval = cursor ? 200 : RETRY_DELAY_MS;
        await delay(Math.max(0, interval - (Date.now() - began)), undefined, {
          signal,
        });
      } catch (error) {
        if (signal.aborted) return;
        throw error;
      }
    }
  }

  const dispatch = async (
    executable: WorkerExecutable,
    request:
      | { kind: "start"; spec: unknown }
      | { kind: "resume"; runId: string; expectedAttemptId: string },
  ): Promise<RecordedRunLaunch> => {
    assertOpen();
    if (request.kind === "start") {
      const spec = RecordedRunSpecSchema.parse(request.spec);
      const launched = await launchLocalWorker({
        runId: spec.runId,
        databasePath: resolved,
        executable,
      });
      // One shot: a lost acknowledgement is the caller's uncertainty,
      // never retried by this client.
      const snapshot = await workerRequest(launched.socketPath, {
        protocolVersion: 1,
        method: "start",
        spec,
      });
      return {
        socketPath: launched.socketPath,
        logPath: launched.logPath,
        snapshot,
      };
    }
    const launched = await launchLocalWorker({
      runId: request.runId,
      databasePath: resolved,
      executable,
    });
    const snapshot = await workerRequest(launched.socketPath, {
      protocolVersion: 1,
      method: "resume",
      expectedAttemptId: request.expectedAttemptId,
    });
    return {
      socketPath: launched.socketPath,
      logPath: launched.logPath,
      snapshot,
    };
  };

  return {
    databasePath: resolved,
    list: () => {
      assertOpen();
      return store.list();
    },
    observe,
    watch,
    start: (spec, executable) => dispatch(executable, { kind: "start", spec }),
    resume: (runId, expectedAttemptId, executable) =>
      dispatch(executable, { kind: "resume", runId, expectedAttemptId }),
    requestControl: (runId, intent, expectedRevision) => {
      assertOpen();
      return store.requestControl(runId, intent, expectedRevision);
    },
    resolveApproval: (runId, approvalId, decision) => {
      assertOpen();
      return store.resolveApproval(runId, approvalId, decision);
    },
    close: () => {
      closing ??= (async () => {
        closed = true;
        lifetime.abort();
        await Promise.allSettled([...reads]);
        store.close();
      })();
      return closing;
    },
  };
}
