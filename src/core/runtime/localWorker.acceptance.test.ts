import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  RunRecoveryBlockedError,
  resumeRecordedAgent,
} from "../api/recordedRun";
import { resolveWorkerEndpoint } from "./localWorkerEndpoint";
import type { WorkerSnapshot } from "./localWorkerProtocol";
import { workerRequest } from "./localWorkerTransport";
import { openSqliteRunStore } from "./sqliteRunStore";

const sessionGet = vi.hoisted(() => vi.fn());

vi.mock("../session", () => ({ get: sessionGet, create: sessionGet }));

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

let tempDirs: string[] = [];
const pidFiles = new Set<string>();
let target: Server | undefined;
let targetHits = 0;
let targetPort = 0;
let store: Store | undefined;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function fixtureDirs() {
  const base = tempDir("worker-fixture-");
  pidFiles.add(join(base, "runs.sqlite.fixture-pid"));
  return {
    base,
    dbPath: join(base, "runs.sqlite"),
    dataDir: join(base, "pensar-data"),
    cwd: tempDir("worker-cwd-"),
    logPath: join(base, "worker.log"),
  };
}

function specFor(
  dirs: ReturnType<typeof fixtureDirs>,
  runId: string,
  approval = false,
) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId,
    prompt: "Request the target homepage once and summarize the response.",
    system: "Custom base system for recovery acceptance.",
    target: `http://127.0.0.1:${targetPort}`,
    model: "claude-haiku-4-5",
    activeTools: ["http_request"],
    environment: { kind: "local", cwd: dirs.cwd },
    scope: {
      version: 1,
      allowedHosts: ["127.0.0.1"],
      allowedPorts: [targetPort],
      strictScope: true,
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
    },
    credentialRefs: [],
    limits: { maxModelAttempts: 4 },
    ...(approval ? { approval: { requiredTools: ["http_request"] } } : {}),
  };
}

async function launchWorker(
  dirs: ReturnType<typeof fixtureDirs>,
  runId: string,
  scenario: string,
) {
  const sessionRoot = join(dirs.dataDir, "sessions", `ses_${runId}`);
  const script = join(
    import.meta.dirname,
    "testfixtures/localWorkerLauncher.ts",
  );
  const launcher = spawn("bun", [script], {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      APEX_WORKER_SCENARIO: scenario,
      APEX_WORKER_DB: dirs.dbPath,
      APEX_WORKER_DATA_DIR: dirs.dataDir,
      APEX_WORKER_CWD: dirs.cwd,
      APEX_WORKER_SESSION_ROOT: sessionRoot,
      APEX_WORKER_PORT: String(targetPort),
      APEX_WORKER_RUN_ID: runId,
      APEX_WORKER_LAUNCH_LOG: dirs.logPath,
    },
  });
  let stdout = "";
  let stderr = "";
  // Attached before any await: a fast launcher exit must not orphan it.
  const exited = new Promise<number>((resolve) =>
    launcher.once("close", (code) => resolve(code ?? 0)),
  );
  launcher.stdout!.on("data", (c) => (stdout += c));
  launcher.stderr!.on("data", (c) => (stderr += c));
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () =>
        reject(
          new Error(
            `launcher did not become ready.\nstdout=${stdout}\nstderr=${stderr}`,
          ),
        ),
      25000,
    );
    exited.then((code) => {
      clearTimeout(timer);
      reject(
        new Error(
          `launcher exited ${code} before readiness.\nstdout=${stdout}\nstderr=${stderr}`,
        ),
      );
    });
    launcher.stdout!.on("data", () => {
      if (stdout.includes("LAUNCHED")) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
  const endpoint = await resolveWorkerEndpoint(dirs.dbPath, runId);
  return { socketPath: endpoint.socketPath, exited };
}

async function killWorker(pid: number): Promise<void> {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Already gone.
  }
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
      await new Promise((r) => setTimeout(r, 50));
    } catch {
      return;
    }
  }
}

async function waitFor<T>(
  poll: () => Promise<T | undefined>,
  ms = 15000,
): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await poll();
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 100));
  }
}

/** The parent's session.get returns the fixture session the child saved. */
function mockSessionGet(dirs: ReturnType<typeof fixtureDirs>, runId: string) {
  const sessionPath = join(
    dirs.dataDir,
    "sessions",
    `ses_${runId}`,
    "session.json",
  );
  sessionGet.mockImplementation(async () =>
    JSON.parse(readFileSync(sessionPath, "utf8")),
  );
}

function snapshotFor(socketPath: string): Promise<WorkerSnapshot> {
  return workerRequest(socketPath, { protocolVersion: 1, method: "snapshot" });
}

function startRun(socketPath: string, spec: ReturnType<typeof specFor>) {
  return workerRequest(socketPath, {
    protocolVersion: 1,
    method: "start",
    spec,
  });
}

beforeAll(async () => {
  tempDirs = [];
  targetHits = 0;
  target = createServer((req, res) => {
    if (req.method === "POST") {
      targetHits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(204);
    res.end();
  });
  await new Promise<void>((resolve) => target!.listen(0, "127.0.0.1", resolve));
  targetPort = (target!.address() as { port: number }).port;
});

afterAll(async () => {
  if (target) {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 5000);
      target!.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  targetHits = 0;
});

afterEach(async () => {
  for (const path of pidFiles) {
    try {
      await killWorker(Number(readFileSync(path, "utf8")));
    } catch {
      /* The fixture may fail before execution starts. */
    }
  }
  pidFiles.clear();
  store?.close();
  store = undefined;
});

describe("detached local workers", () => {
  it("survives the launcher's exit and completes the run", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_detached";
    const { socketPath, exited } = await launchWorker(dirs, runId, "complete");

    // The launcher is a real process; it must exit before the run finishes.
    const launcherExit = exited;
    await startRun(socketPath, specFor(dirs, runId));
    expect(await launcherExit).toBe(0);

    await waitFor(async () =>
      (await store!.get(runId))?.status === "completed" ? true : undefined,
    );
    expect(targetHits).toBe(1);
  });

  it("an endpoint approve after the launcher exited unblocks a pending approval", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_approve";
    const { socketPath, exited } = await launchWorker(
      dirs,
      runId,
      "approval-hold",
    );
    const launcherExit = exited;
    await startRun(socketPath, specFor(dirs, runId, true));
    expect(await launcherExit).toBe(0);

    const approval = await waitFor(async () => {
      const list = await store!.listApprovals(runId);
      return list[0] ?? undefined;
    });
    expect(approval.state).toBe("pending");

    await workerRequest(socketPath, {
      protocolVersion: 1,
      method: "approve",
      approvalId: approval.approvalId,
    });

    await waitFor(async () =>
      (await store!.get(runId))?.status === "completed" ? true : undefined,
    );
    expect(targetHits).toBe(1);
  });

  it("a competing launch against a live run cannot duplicate execution", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_competing";
    const { socketPath } = await launchWorker(dirs, runId, "approval-hold");
    await startRun(socketPath, specFor(dirs, runId, true));
    const approval = await waitFor(async () => {
      const list = await store!.listApprovals(runId);
      return list[0] ?? undefined;
    });
    const hitsWhenPending = targetHits;

    // A serial second launcher reuses the live worker's endpoint.
    const second = await launchWorker(dirs, runId, "approval-hold");
    expect(await second.exited).toBe(0);
    expect(second.socketPath).toBe(socketPath);
    expect(targetHits).toBe(hitsWhenPending);

    // The duplicate start on the LIVE worker is a no-op, not a re-run.
    const dup = await startRun(socketPath, specFor(dirs, runId, true));
    expect(dup.phase).not.toBe("idle");

    await workerRequest(socketPath, {
      protocolVersion: 1,
      method: "approve",
      approvalId: approval.approvalId,
    });
    await waitFor(async () =>
      (await store!.get(runId))?.status === "completed" ? true : undefined,
    );
    expect(targetHits).toBe(hitsWhenPending + 1);
    const attempts = await store!.listModelAttempts(runId);
    expect(attempts).toHaveLength(1);
  });

  it("two concurrent launchers on a fresh run converge to one executor", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_race";

    const [a, b] = await Promise.all([
      launchWorker(dirs, runId, "approval-hold"),
      launchWorker(dirs, runId, "approval-hold"),
    ]);
    expect(await a.exited).toBe(0);
    expect(await b.exited).toBe(0);
    expect(a.socketPath).toBe(b.socketPath);
    const socketPath = a.socketPath;
    await startRun(socketPath, specFor(dirs, runId, true));
    const approval = await waitFor(async () => {
      const list = await store!.listApprovals(runId);
      return list[0] ?? undefined;
    });
    const hitsWhenPending = targetHits;

    await workerRequest(socketPath, {
      protocolVersion: 1,
      method: "approve",
      approvalId: approval.approvalId,
    });
    await waitFor(async () =>
      (await store!.get(runId))?.status === "completed" ? true : undefined,
    );
    expect(targetHits).toBe(hitsWhenPending + 1);
    expect(await store!.listModelAttempts(runId)).toHaveLength(1);
  });

  it("pause stays cooperative: pending approval survives, no dispatch, run saves paused", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_pause";
    const { socketPath, exited } = await launchWorker(
      dirs,
      runId,
      "approval-hold",
    );
    await startRun(socketPath, specFor(dirs, runId, true));
    expect(await exited).toBe(0);
    await waitFor(async () => {
      const list = await store!.listApprovals(runId);
      return list[0] ?? undefined;
    });

    const control = await waitFor(
      async () => (await store!.getControl(runId)) ?? undefined,
    );
    await workerRequest(socketPath, {
      protocolVersion: 1,
      method: "pause",
      expectedRevision: control.revision,
    });

    // The pause interrupts the approval wait; the decision stays durable.
    await waitFor(async () =>
      (await store!.get(runId))?.status === "paused" ? true : undefined,
    );
    const approvals = await store!.listApprovals(runId);
    expect(approvals[0]).toMatchObject({ state: "pending" });
    expect(targetHits).toBe(0);
  });

  it("resumes immediately after a settled tool is paused without repeating its effect", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_pause_resume";
    const first = await launchWorker(dirs, runId, "pause-after-settle");
    await startRun(first.socketPath, specFor(dirs, runId));
    expect(await first.exited).toBe(0);
    await waitFor(async () =>
      (await store!.listToolOperations(runId))[0]?.state === "settled"
        ? true
        : undefined,
    );
    const control = (await store.getControl(runId))!;
    await workerRequest(first.socketPath, {
      protocolVersion: 1,
      method: "pause",
      expectedRevision: control.revision,
    });
    writeFileSync(
      `${dirs.dbPath}.continue`,
      "resume the fixture dispatch gate",
    );
    const paused = await waitFor(async () => {
      const record = await store!.get(runId);
      return record?.status === "paused" ? record : undefined;
    });
    const priorWorker = (await snapshotFor(first.socketPath)).workerId;
    const second = await launchWorker(dirs, runId, "complete");
    expect((await snapshotFor(second.socketPath)).workerId).not.toBe(
      priorWorker,
    );
    await workerRequest(second.socketPath, {
      protocolVersion: 1,
      method: "resume",
      expectedAttemptId: paused.attemptId,
    });
    await waitFor(async () =>
      (await store!.get(runId))?.status === "completed" ? true : undefined,
    );
    expect(targetHits).toBe(1);
    expect(await store.listRecoveries(runId)).toHaveLength(1);
  });

  it("aborting an in-flight watch request leaves execution alive", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_watch_abort";
    const { socketPath } = await launchWorker(dirs, runId, "approval-hold");
    await startRun(socketPath, specFor(dirs, runId, true));
    // The approval wait holds execution open for the whole test.
    await waitFor(async () => {
      const list = await store!.listApprovals(runId);
      return list[0] ?? undefined;
    });

    // Watch at the current cursor so it is a genuine in-flight long-poll;
    // then abort it and assert the disconnect was observed while the
    // worker is still executing.
    const before = await snapshotFor(socketPath);
    expect(before.phase).toBe("executing");
    const watchAbort = new AbortController();
    const watch = workerRequest(
      socketPath,
      {
        protocolVersion: 1,
        method: "watch",
        cursor: { workerId: before.workerId, sequence: before.sequence },
      },
      { signal: watchAbort.signal },
    );
    await new Promise((r) => setTimeout(r, 100));
    watchAbort.abort();
    await expect(watch).rejects.toThrow();

    // Execution survived the aborted observation.
    const after = await snapshotFor(socketPath);
    expect(after.phase).toBe("executing");
    expect((await store!.get(runId))?.status).not.toBe("completed");
    expect(targetHits).toBe(0);
  });

  it("worker SIGKILL after an ambiguous effect falls back to blocked recovery", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_kill_ambiguous";
    const { socketPath } = await launchWorker(dirs, runId, "crash-after-post");
    await startRun(socketPath, specFor(dirs, runId));
    // The POST landed (target mutated) AND the intent is committed with no
    // outcome — that combination is the ambiguous effect.
    await waitFor(async () => {
      const ops = await store!.listToolOperations(runId);
      return ops[0]?.state === "started" && targetHits === 1 ? true : undefined;
    });
    const hitsAfterPost = targetHits;
    const recordBefore = (await store!.get(runId))!;
    const attemptsBefore = (await store!.listModelAttempts(runId)).length;

    await killWorker(
      Number(readFileSync(`${dirs.dbPath}.fixture-pid`, "utf8")),
    );

    mockSessionGet(dirs, runId);
    const blocked = await resumeRecordedAgent({ runId, store }).catch(
      (e: unknown) => e,
    );
    expect(blocked).toBeInstanceOf(RunRecoveryBlockedError);
    expect((blocked as RunRecoveryBlockedError).blockers.join(" ")).toMatch(
      /unknown|started/i,
    );
    expect(targetHits).toBe(hitsAfterPost);
    expect((await store!.listModelAttempts(runId)).length).toBe(attemptsBefore);
    expect((await store!.get(runId))!.attemptId).toBe(recordBefore.attemptId);
    expect(await store!.listRecoveries(runId)).toEqual([]);
  });

  it("a killed worker with a settled effect resumes through a new worker without re-POST", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const runId = "run_worker_kill_settled";
    const first = await launchWorker(dirs, runId, "crash-after-settle");
    await startRun(first.socketPath, specFor(dirs, runId));
    await waitFor(async () => {
      const ops = await store!.listToolOperations(runId);
      return ops[0]?.state === "settled" ? true : undefined;
    });
    const hitsAfterSettle = targetHits;
    const staleAttemptId = (await store!.get(runId))!.attemptId;
    await killWorker(
      Number(readFileSync(`${dirs.dbPath}.fixture-pid`, "utf8")),
    );

    // A replacement worker resumes with the explicit expected attempt.
    const second = await launchWorker(dirs, runId, "complete");
    mockSessionGet(dirs, runId);
    const resumed = await workerRequest(second.socketPath, {
      protocolVersion: 1,
      method: "resume",
      expectedAttemptId: staleAttemptId,
    });
    expect(resumed.phase).toBe("executing");

    await waitFor(async () =>
      (await store!.get(runId))?.status === "completed" ? true : undefined,
    );
    const record = (await store!.get(runId))!;
    expect(record.attemptId).not.toBe(staleAttemptId);
    expect(targetHits).toBe(hitsAfterSettle); // no HTTP re-execution
    const recoveries = await store!.listRecoveries(runId);
    expect(recoveries).toHaveLength(1);
  });
});
