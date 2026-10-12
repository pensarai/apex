import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { resolveWorkerEndpoint } from "./localWorkerEndpoint";
import { serveWorkerTransport } from "./localWorkerTransport";
import {
  openRecordedRunClient,
  type RecordedRunView,
} from "./recordedRunClient";
import { RecordedRunSpecSchema } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

it("reconnects through real sockets without changing a foreground-owned run", async () => {
  const root = await mkdtemp(join(tmpdir(), "apex-client-"));
  const databasePath = join(root, "runs.sqlite");
  const store = await openSqliteRunStore(databasePath);
  const spec = RecordedRunSpecSchema.parse({
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_client_reconnect",
    prompt: "Local client check",
    target: "local",
    model: "claude-haiku-4-5",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: root },
    scope: { version: 1, strictScope: true },
  });
  const { record } = await store.admit(spec);
  await store.initializeControl(spec.runId, record.attemptId);
  await store.transition(spec.runId, record.attemptId, "running");
  const executionLock = await store.acquireExecutionLock(spec.runId);
  await store.commitContext(spec.runId, record.attemptId, 0, {
    kind: "replace",
    system: null,
    messages: [{ role: "user", content: "Initial request" }],
  });
  const client = await openRecordedRunClient(databasePath);
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 10_000);
  const endpoint = await resolveWorkerEndpoint(databasePath, spec.runId);
  let transport: Awaited<ReturnType<typeof serveWorkerTransport>> | undefined;
  const views = client.watch(spec.runId, abort.signal);
  const matching = async (predicate: (view: RecordedRunView) => boolean) => {
    for (;;) {
      const next = await views.next();
      if (next.done) throw new Error("Observer ended before expected state");
      if (predicate(next.value)) return next.value;
    }
  };
  const connect = (workerId: string) =>
    serveWorkerTransport({
      socketPath: endpoint.socketPath,
      handle: async () => ({
        protocolVersion: 1,
        workerId,
        runId: spec.runId,
        phase: "executing",
        sequence: 1,
        observation: await store.observe(spec.runId),
      }),
    });
  try {
    const offline = await matching((view) => view.connection === "offline");
    expect(offline.observation.record?.status).toBe("running");
    expect(offline.worker).toBeNull();
    await store.commitContext(spec.runId, record.attemptId, 1, {
      kind: "append",
      messages: [{ role: "assistant", content: "Foreground progress" }],
    });
    const progressed = await matching(
      (view) => view.observation.context?.revision === 2,
    );
    expect(progressed.connection).toBe("offline");
    expect(progressed.observation.record?.updatedAt).toBe(
      offline.observation.record?.updatedAt,
    );
    transport = await connect("worker-first");
    await matching((view) => view.worker?.workerId === "worker-first");
    await transport.close();
    transport = undefined;
    await matching((view) => view.connection === "offline");
    transport = await connect("worker-replacement");
    const replacement = await matching(
      (view) => view.worker?.workerId === "worker-replacement",
    );
    expect(replacement.connection).toBe("connected");
    expect(replacement.observation.record?.attemptId).toBe(record.attemptId);

    abort.abort();
    await views.return(undefined);
    await client.close();
    expect((await store.getControl(spec.runId))?.intent).toBe("run");
    expect((await store.get(spec.runId))?.status).toBe("running");
    expect(await store.listModelAttempts(spec.runId)).toEqual([]);
  } finally {
    clearTimeout(timer);
    abort.abort();
    await views.return(undefined);
    await client.close();
    await transport?.close();
    executionLock.release();
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});
