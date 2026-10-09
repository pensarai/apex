import { randomUUID } from "node:crypto";
import { unlink } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { acquireLocalRunLock } from "./localRunLock";
import { resolveWorkerEndpoint } from "./localWorkerEndpoint";
import type { LocalWorkerRequest, WorkerSnapshot } from "./localWorkerProtocol";
import {
  LocalWorkerRequestRejectedError,
  serveWorkerTransport,
} from "./localWorkerTransport";
import { RecordedRunSpecSchema } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

type ExecutionRequest = Extract<
  LocalWorkerRequest,
  { method: "start" | "resume" }
>;

export interface LocalRunWorkerOptions {
  runId: string;
  databasePath: string;
  execute(input: {
    request: ExecutionRequest;
    store: Awaited<ReturnType<typeof openSqliteRunStore>>;
    signal: AbortSignal;
  }): Promise<unknown>;
  idleTimeoutMs?: number;
  settledTimeoutMs?: number;
}

export async function serveLocalRunWorker(
  options: LocalRunWorkerOptions,
): Promise<void> {
  const { runId, databasePath } = options;
  const store = await openSqliteRunStore(databasePath);
  let releaseHost: (() => void) | undefined;
  let transport: Awaited<ReturnType<typeof serveWorkerTransport>> | undefined;
  let expiry: ReturnType<typeof setTimeout> | undefined;
  const controller = new AbortController();
  const abort = () => {
    controller.abort();
    if (phase !== "executing") finish();
  };
  const workerId = randomUUID();
  let phase: WorkerSnapshot["phase"] = "idle";
  let error: WorkerSnapshot["error"];
  let invocation: ExecutionRequest | undefined;
  let execution: Promise<void> | undefined;
  let sequence = 0;
  let encoded = "";
  let cached: WorkerSnapshot | undefined;
  let readAt = 0;
  let reading: Promise<WorkerSnapshot> | undefined;
  let mutations = Promise.resolve();
  let closing = false;
  let finish!: () => void;
  const finished = new Promise<void>((resolve) => {
    finish = () => {
      closing = true;
      resolve();
    };
  });

  const expire = (ms: number) => {
    clearTimeout(expiry);
    expiry = setTimeout(finish, ms);
  };
  const snapshot = async (force = false): Promise<WorkerSnapshot> => {
    if (reading) {
      const current = await reading;
      if (!force) return current;
    }
    if (!force && cached && Date.now() - readAt < 200) return cached;
    reading = (async () => {
      const observation = await store.observe(runId);
      const state = { phase, observation, ...(error ? { error } : {}) };
      const next = JSON.stringify(state);
      if (next !== encoded) {
        encoded = next;
        sequence += 1;
      }
      cached = {
        protocolVersion: 1,
        workerId,
        runId,
        sequence,
        ...state,
      };
      readAt = Date.now();
      return cached;
    })();
    try {
      return await reading;
    } finally {
      reading = undefined;
    }
  };

  const start = async (request: ExecutionRequest) => {
    const saved = await store.get(runId);
    if (closing) {
      throw new LocalWorkerRequestRejectedError("Worker is shutting down");
    }
    if (request.method === "start") {
      const parsed = RecordedRunSpecSchema.safeParse(request.spec);
      if (!parsed.success) {
        throw new LocalWorkerRequestRejectedError(
          `Invalid run spec: ${parsed.error.message}`,
        );
      }
      const spec = parsed.data;
      if (spec.runId !== runId) {
        throw new LocalWorkerRequestRejectedError("Worker run ID mismatch");
      }
      if (saved && JSON.stringify(saved.spec) !== JSON.stringify(spec)) {
        throw new LocalWorkerRequestRejectedError(
          "Run ID already has a different specification",
        );
      }
      if (invocation && invocation.method !== "start") {
        throw new LocalWorkerRequestRejectedError(
          "Worker already accepted a recovery request",
        );
      }
      if (saved || invocation) {
        if (phase === "idle") {
          phase = "settled";
          expire(options.settledTimeoutMs ?? 2_000);
        }
        return;
      }
    } else {
      if (invocation) {
        if (
          invocation.method !== "resume" ||
          invocation.expectedAttemptId !== request.expectedAttemptId
        ) {
          throw new LocalWorkerRequestRejectedError(
            "Worker already accepted a different execution",
          );
        }
        return;
      }
      if (!saved || saved.attemptId !== request.expectedAttemptId) {
        throw new LocalWorkerRequestRejectedError(
          "Recovery attempt changed; inspect the run again",
        );
      }
    }

    invocation = request;
    phase = "executing";
    clearTimeout(expiry);
    // Only worker signals control execution; a request's signal is observation-only.
    execution = Promise.resolve()
      .then(() =>
        options.execute({ request, store, signal: controller.signal }),
      )
      .then(async (value) => {
        // started:false with a still-admitted record means another
        // invocation admitted this run; stopped/paused/terminal
        // no-starts are legitimate outcomes.
        if (
          typeof value === "object" &&
          value !== null &&
          "started" in value &&
          value.started === false
        ) {
          const saved = await store.get(runId);
          if (
            saved &&
            (saved.status === "admitted" || saved.status === "running")
          ) {
            error = {
              message: `Run ${runId} is already admitted (last status: ${saved.status}); this worker did not start it. Inspect the run before resuming`,
            };
            console.error(
              `Local worker did not own execution: ${error.message}`,
            );
          }
        }
      })
      .catch((cause: unknown) => {
        error = {
          message: cause instanceof Error ? cause.message : String(cause),
          ...(cause instanceof Error &&
          "blockers" in cause &&
          Array.isArray(cause.blockers) &&
          cause.blockers.every((item) => typeof item === "string")
            ? { blockers: cause.blockers as string[] }
            : {}),
        };
        console.error(`Local worker execution failed: ${error.message}`);
      })
      .finally(() => {
        phase = "settled";
        readAt = 0;
        expire(options.settledTimeoutMs ?? 2_000);
      });
  };

  const mutate = async (request: LocalWorkerRequest) => {
    if (closing) {
      throw new LocalWorkerRequestRejectedError("Worker is shutting down");
    }
    switch (request.method) {
      case "start":
      case "resume":
        await start(request);
        break;
      case "pause":
      case "stop":
        await store.requestControl(
          runId,
          request.method,
          request.expectedRevision,
        );
        break;
      case "approve":
      case "reject":
        await store.resolveApproval(
          runId,
          request.approvalId,
          request.method === "approve" ? "approved" : "denied",
        );
        break;
    }
    readAt = 0;
    return snapshot(true);
  };

  try {
    const endpoint = await resolveWorkerEndpoint(databasePath, runId);
    const lock = await acquireLocalRunLock(runId, endpoint.lockDatabasePath);
    releaseHost = () => lock.release();
    // A failed connection alone never authorizes removing another host's socket.
    await unlink(endpoint.socketPath).catch((cause: NodeJS.ErrnoException) => {
      if (cause.code !== "ENOENT") throw cause;
    });
    transport = await serveWorkerTransport({
      socketPath: endpoint.socketPath,
      async handle(request, signal) {
        if (request.method === "snapshot") return snapshot();
        if (request.method === "watch") {
          const until = Date.now() + 1_000;
          do {
            signal.throwIfAborted();
            const value = await snapshot();
            if (
              !request.cursor ||
              request.cursor.workerId !== value.workerId ||
              request.cursor.sequence !== value.sequence ||
              value.phase === "settled"
            ) {
              return value;
            }
            await delay(200, undefined, { signal });
          } while (Date.now() < until);
          return snapshot();
        }
        const result = mutations.then(() => mutate(request));
        mutations = result.then(
          () => undefined,
          () => undefined,
        );
        return result;
      },
    });
    process.on("SIGINT", abort);
    process.on("SIGTERM", abort);
    expire(options.idleTimeoutMs ?? 30_000);
    await finished;
  } finally {
    closing = true;
    clearTimeout(expiry);
    process.off("SIGINT", abort);
    process.off("SIGTERM", abort);
    try {
      await transport?.close();
      await mutations;
      await execution;
    } finally {
      store.close();
      releaseHost?.();
    }
  }
}
