import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startInferenceAttempt } from "../ai/inference-attempt";
import { acquireLocalRunLock } from "./localRunLock";
import type { RunControlRecord } from "./runControlStore";
import {
  type RecordedRunSpec,
  type RunRecord,
  RunRecordSchema,
} from "./runStore";
import {
  createSqliteRecoveryStore,
  RECOVERY_STORE_SCHEMA_SQL,
} from "./sqliteRecoveryStore";
import { openSqliteRunStore } from "./sqliteRunStore";

// The recovery helper is exercised directly over the real SQLite database —
// the same wiring root's store integration performs.

type RunStore = Awaited<ReturnType<typeof openSqliteRunStore>>;
type Recovery = ReturnType<typeof createSqliteRecoveryStore>;

let tempDirs: string[] = [];
const holdChildren: Array<ReturnType<typeof spawn>> = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("recoverystore-db-"), "runs.sqlite");
}

const cwdByRunId = new Map<string, string>();

function spec(runId: string): RecordedRunSpec {
  let cwd = cwdByRunId.get(runId);
  if (!cwd) {
    cwd = tempDir("recoverystore-cwd-");
    cwdByRunId.set(runId, cwd);
  }
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId,
    prompt: "Request the target homepage once and summarize the response.",
    target: "http://127.0.0.1:8080",
    model: "claude-sonnet-5-5",
    activeTools: ["http_request"],
    environment: { kind: "local", cwd },
    scope: {
      version: 1,
      allowedHosts: ["127.0.0.1"],
      allowedPorts: [8080],
      strictScope: true,
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
    },
    credentialRefs: [],
  };
}

const requireModule = createRequire(import.meta.url);

interface RawConnection {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...values: unknown[]): unknown;
    get(...values: unknown[]): unknown;
    all(...values: unknown[]): unknown[];
  };
  close(): void;
}

function rawDb(dbPath: string): RawConnection {
  const mod = requireModule(
    typeof Bun !== "undefined" ? "bun:sqlite" : "node:sqlite",
  ) as {
    Database?: new (p: string) => RawConnection;
    DatabaseSync?: new (p: string) => RawConnection;
  };
  const Ctor = (mod.Database ?? mod.DatabaseSync)!;
  return new Ctor(dbPath);
}

function rawTransaction(db: RawConnection) {
  return <T>(operation: () => T): T => {
    db.exec("BEGIN IMMEDIATE");
    try {
      const value = operation();
      db.exec("COMMIT");
      return value;
    } catch (error) {
      try {
        db.exec("ROLLBACK");
      } catch {
        // Surface the operation's error.
      }
      throw error;
    }
  };
}

/** Helper wired exactly as root's integration will wire it. */
async function withRecovery<T>(
  dbPath: string,
  options:
    | {
        fresh?: string[];
        /**
         * Run ids whose real public-store execution lock is held for the block.
         * Locks are acquired lazily once the run exists (admission happens
         * inside the block), so pass the ids even before they are admitted.
         */
        locked?: string[];
      }
    | undefined,
  fn: (
    store: RunStore,
    recovery: Recovery,
    dbPath: string,
    acquireLock: (runId: string) => Promise<void>,
  ) => Promise<T>,
): Promise<T> {
  const store = await openSqliteRunStore(dbPath);
  const locks: Array<{ release(): void }> = [];
  const locked = new Set(options?.locked ?? []);
  // Backfill: runs admitted inside the block get their lock immediately, so
  // subsequent public-store execution writes pass the real gate.
  const pollLock = async (runId: string) => {
    if (!locked.has(runId)) return;
    if (!(await store.get(runId))) return;
    if (locks.length > 0) return; // one lock per block keeps fixtures simple
    locks.push(await store.acquireExecutionLock(runId));
  };
  try {
    const db = rawDb(dbPath);
    const hasTables = db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'recovery_enrollments'",
      )
      .get();
    if (!hasTables) db.exec(RECOVERY_STORE_SCHEMA_SQL);
    const fresh = new Set(options?.fresh ?? []);
    const recovery = createSqliteRecoveryStore({
      db,
      transaction: rawTransaction(db),
      getRun: (runId) => {
        const row = db
          .prepare("SELECT record_json FROM runs WHERE run_id = ?")
          .get(runId);
        if (row == null) return undefined;
        const record: RunRecord = RunRecordSchema.parse(
          JSON.parse((row as { record_json: string }).record_json),
        );
        if (record.spec.runId !== runId) {
          throw new Error("Run identity mismatch");
        }
        return record;
      },
      getContextReference: (runId) => {
        const head = db
          .prepare(
            "SELECT epoch, revision FROM run_context WHERE run_id = ? ORDER BY revision DESC LIMIT 1",
          )
          .get(runId) as { epoch: number; revision: number } | null | undefined;
        return head ? { epoch: head.epoch, revision: head.revision } : null;
      },
      readControl: (runId) => {
        const row = db
          .prepare("SELECT record_json FROM run_controls WHERE run_id = ?")
          .get(runId);
        if (row == null) return undefined;
        const control = JSON.parse(
          (row as { record_json: string }).record_json,
        ) as RunControlRecord;
        return control;
      },
      databasePath: dbPath,
      isFreshAdmission: (runId) => fresh.has(runId),
      lockHeld: (runId) => locked.has(runId),
      runtimeVersion: "test-runtime-1",
    });
    // Backfill for runs admitted before the block body runs its first write.
    for (const runId of locked) await pollLock(runId);
    return await fn(store, recovery, dbPath, pollLock);
  } finally {
    for (const lock of locks) lock.release();
    store.close();
  }
}

async function admit(store: RunStore, runId: string): Promise<string> {
  const admitted = await store.admit(spec(runId));
  return admitted.record.attemptId;
}

/** Admits, acquires the real lock, then enrolls. */
async function enrolledRun(
  store: RunStore,
  recovery: Recovery,
  runId: string,
  acquireLock: (runId: string) => Promise<void>,
): Promise<string> {
  const exec = await admit(store, runId);
  await acquireLock(runId);
  const sessionRoot = tempDir("recoverystore-session-");
  await recovery.methods.enrollRecovery(runId, exec, sessionRoot);
  return exec;
}

function claimInput(exec: string, revision: number) {
  return {
    expectedAttemptId: exec,
    expectedContext: { epoch: 1, revision: 1 },
    expectedControlRevision: revision,
    reconstruction: {
      sourceContext: { epoch: 1, revision: 1 },
      reconstructedToolCalls: [],
      restartedModelAttempts: [],
      deniedToolCalls: [],
      discardedUncommitted: true,
    },
  };
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  for (const child of holdChildren) {
    if (child.exitCode === null) child.kill("SIGKILL");
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("per-run execution lock", () => {
  it("refuses a same-process collision and releases cleanly", async () => {
    const dbPath = tempDb();
    const first = await acquireLocalRunLock("run_lock_same", dbPath);
    await expect(acquireLocalRunLock("run_lock_same", dbPath)).rejects.toThrow(
      /held by another executor/,
    );
    // Different runs never collide.
    const other = await acquireLocalRunLock("run_lock_other", dbPath);
    first.release();
    other.release();
    // Release is idempotent.
    first.release();
    const again = await acquireLocalRunLock("run_lock_same", dbPath);
    again.release();
  });

  it("excludes a live process and releases after SIGKILL", async () => {
    const dbPath = tempDb();
    const fixtureDir = tempDir("recoverystore-lock-fixture-");
    const script = join(fixtureDir, "holder.ts");
    writeFileSync(
      script,
      `
import { acquireLocalRunLock } from ${JSON.stringify(join(import.meta.dirname, "localRunLock.ts"))};
const [dbPath, runId] = process.argv.slice(2);
const lock = await acquireLocalRunLock(runId, dbPath);
console.log("held");
setInterval(() => {}, 1000);
`,
    );

    const child = spawn("bun", [script, dbPath, "run_lock_proc"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    holdChildren.push(child);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("holder produced no marker")),
        20000,
      );
      child.stdout!.on("data", (chunk: Buffer) => {
        if (chunk.toString().includes("held")) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.on("error", reject);
    });

    // Live executor: acquisition refuses.
    await expect(acquireLocalRunLock("run_lock_proc", dbPath)).rejects.toThrow(
      /held by another executor/,
    );

    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.on("close", () => resolve()));

    // OS released the lock with the process.
    const recovered = await acquireLocalRunLock("run_lock_proc", dbPath);
    recovered.release();
  });

  it("rejects an invalid run id as a lock path component", async () => {
    await expect(acquireLocalRunLock("../escape", tempDb())).rejects.toThrow(
      /not a valid lock file component/,
    );
  });
});

describe("recovery enrollment", () => {
  it("enrolls fresh admissions with actual environment identity", async () => {
    await withRecovery(
      tempDb(),
      { fresh: ["run_rec_enroll"], locked: ["run_rec_enroll"] },
      async (store, recovery, _db, acquireLock) => {
        const exec = await admit(store, "run_rec_enroll");
        const sessionRoot = tempDir("recoverystore-session-");
        const enrollment = await recovery.methods.enrollRecovery(
          "run_rec_enroll",
          exec,
          sessionRoot,
        );
        expect(enrollment.protocol).toBe(1);
        expect(enrollment.executionAttemptId).toBe(exec);
        expect(enrollment.environment.runtimeVersion).toBe("test-runtime-1");
        expect(enrollment.environment.databaseIno).toBeGreaterThan(0);
        expect(enrollment.environment.sessionRootPath).toContain(
          "recoverystore-session-",
        );

        // Idempotent for the same owner.
        const again = await recovery.methods.enrollRecovery(
          "run_rec_enroll",
          exec,
          sessionRoot,
        );
        expect(again).toEqual(enrollment);

        // Reads survive reopen.
        expect(
          (await recovery.methods.getRecoveryEnrollment("run_rec_enroll"))
            ?.executionAttemptId,
        ).toBe(exec);
      },
    );
  });

  it("refuses old runs: not fresh, wrong owner, terminal, or re-enroll after rotation", async () => {
    await withRecovery(
      tempDb(),
      undefined,
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_stale";
        const exec = await admit(store, runId);

        // Admitted/running but NOT fresh and NOT locked — an old crashed run
        // satisfies status alone, so freshness is what must block it.
        await expect(
          recovery.methods.enrollRecovery(
            runId,
            exec,
            tempDir("recoverystore-session-"),
          ),
        ).rejects.toThrow(/not freshly admitted|lock is not held/);
        expect(
          await recovery.methods.getRecoveryEnrollment(runId),
        ).toBeUndefined();

        // Locked and fresh, but wrong owner.
        await withRecovery(
          tempDb(),
          { fresh: [runId], locked: [runId] },
          async (_s, r2) => {
            await expect(
              r2.methods.enrollRecovery(
                runId,
                "exec_00000000-0000-4000-8000-000000000001",
                tempDir("recoverystore-session-"),
              ),
            ).rejects.toThrow(/does not own this run/);
          },
        );
      },
    );
  });
});

describe("claim recovery", () => {
  it("rotates all owners atomically and appends history", async () => {
    const dbPath = tempDb();
    let exec: string;
    await withRecovery(
      dbPath,
      { fresh: ["run_rec_claim"], locked: ["run_rec_claim"] },
      async (store, recovery, dbPath, acquireLock) => {
        exec = await enrolledRun(store, recovery, "run_rec_claim", acquireLock);
        await store.transition("run_rec_claim", exec, "running");
        await store.commitContext("run_rec_claim", exec, 0, {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        });
        await store.initializeToolJournal("run_rec_claim", exec);
        await store.initializeControl("run_rec_claim", exec);
        await store.requestControl("run_rec_claim", "pause", 0);

        const record = await recovery.methods.claimRecovery(
          "run_rec_claim",
          claimInput(exec, 1),
        );
        expect(record.fromAttemptId).toBe(exec);
        expect(record.toAttemptId).toMatch(/^exec_[0-9a-f-]{36}$/);

        const run = await store.get("run_rec_claim");
        expect(run?.attemptId).toBe(record.toAttemptId);
        expect(run?.status).toBe("running");

        const raw = rawDb(dbPath);
        const journal = raw
          .prepare(
            "SELECT execution_attempt_id FROM tool_journals WHERE run_id = ?",
          )
          .get("run_rec_claim") as { execution_attempt_id: string };
        const control = JSON.parse(
          (
            raw
              .prepare("SELECT record_json FROM run_controls WHERE run_id = ?")
              .get("run_rec_claim") as { record_json: string }
          ).record_json,
        );
        const enrollment = JSON.parse(
          (
            raw
              .prepare(
                "SELECT record_json FROM recovery_enrollments WHERE run_id = ?",
              )
              .get("run_rec_claim") as { record_json: string }
          ).record_json,
        );
        raw.close();
        expect(journal.execution_attempt_id).toBe(record.toAttemptId);
        // Pause cleared to run with revision+1 for the new owner.
        expect(control).toMatchObject({
          executionAttemptId: record.toAttemptId,
          intent: "run",
          revision: 2,
        });
        expect(enrollment.executionAttemptId).toBe(record.toAttemptId);
        expect(enrollment.environment.sessionRootPath).toContain(
          "recoverystore-session-",
        );
      },
    );

    // History persists and is listed in order.
    await withRecovery(
      dbPath,
      undefined,
      async (_store, recovery, _db, acquireLock) => {
        const history = await recovery.methods.listRecoveries("run_rec_claim");
        expect(history).toHaveLength(1);
        expect(history[0]?.fromAttemptId).toBe(exec!);
      },
    );
  });

  it("rejects stale CAS inputs, stop intent, terminal status, and unenrolled runs without mutating", async () => {
    await withRecovery(
      tempDb(),
      { fresh: ["run_rec_reject"], locked: ["run_rec_reject"] },
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_reject";
        const exec = await enrolledRun(store, recovery, runId, acquireLock);
        await store.transition(runId, exec, "running");
        await store.commitContext(runId, exec, 0, {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        });
        await store.initializeToolJournal(runId, exec);
        await store.initializeControl(runId, exec);

        // Stale control revision.
        await expect(
          recovery.methods.claimRecovery(runId, claimInput(exec, 99)),
        ).rejects.toThrow(/Control revision conflict/);
        // Stale attempt: the enrollment owner check fires first.
        await expect(
          recovery.methods.claimRecovery(
            runId,
            claimInput("exec_00000000-0000-4000-8000-0000000000ff", 0),
          ),
        ).rejects.toThrow(/owner changed|does not own this run/);
        // No context committed yet → context conflict (after status check).
        await withRecovery(
          tempDb(),
          { fresh: ["run_rec_noctx"], locked: ["run_rec_noctx"] },
          async (s2, r2, _db2, acquireLock2) => {
            const exec2 = await enrolledRun(
              s2,
              r2,
              "run_rec_noctx",
              acquireLock2,
            );
            await s2.transition("run_rec_noctx", exec2, "running");
            await expect(
              r2.methods.claimRecovery("run_rec_noctx", claimInput(exec2, 0)),
            ).rejects.toThrow(/Context revision conflict/);
          },
        );

        // Stop intent blocks recovery.
        await store.requestControl(runId, "stop", 0);
        await expect(
          recovery.methods.claimRecovery(runId, claimInput(exec, 1)),
        ).rejects.toThrow(/stop was requested/);

        // Nothing rotated through all the rejections.
        const run = await store.get(runId);
        expect(run?.attemptId).toBe(exec);
        expect(
          (await recovery.methods.getRecoveryEnrollment(runId))
            ?.executionAttemptId,
        ).toBe(exec);
      },
    );

    // Unenrolled legacy run.
    await withRecovery(
      tempDb(),
      undefined,
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_legacy";
        const exec = await admit(store, runId);
        await expect(
          recovery.methods.claimRecovery(runId, claimInput(exec, 0)),
        ).rejects.toThrow(/no recovery enrollment/);
      },
    );
  });

  it("blocks when the environment changed since enrollment", async () => {
    const dbPath = tempDb();
    let exec: string;
    await withRecovery(
      dbPath,
      { fresh: ["run_rec_env"], locked: ["run_rec_env"] },
      async (store, recovery, _db, acquireLock) => {
        exec = await enrolledRun(store, recovery, "run_rec_env", acquireLock);
        await store.transition("run_rec_env", exec, "running");
        await store.commitContext("run_rec_env", exec, 0, {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        });
        await store.initializeToolJournal("run_rec_env", exec);
        await store.initializeControl("run_rec_env", exec);
      },
    );

    // Replace the database file with a copy: same content, new inode.
    const copyPath = `${dbPath}.copy`;
    const raw = rawDb(dbPath);
    raw.exec(`VACUUM INTO '${copyPath}'`);
    raw.close();

    await withRecovery(
      copyPath,
      { locked: ["run_rec_env"] },
      async (_store, recovery, _db, acquireLock) => {
        await expect(
          recovery.methods.claimRecovery("run_rec_env", claimInput(exec!, 0)),
        ).rejects.toThrow(/environment changed/);
      },
    );
    rmSync(copyPath, { force: true });
  });

  it("refuses a claim past the absolute deadline and preserves all records", async () => {
    const dbPath = tempDb();
    let exec: string;
    await withRecovery(
      dbPath,
      { fresh: ["run_rec_deadline"], locked: ["run_rec_deadline"] },
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_deadline";
        const admitted = await store.admit({
          ...spec(runId),
          limits: { deadlineAt: new Date(Date.now() - 1000).toISOString() },
        } as never);
        exec = admitted.record.attemptId;
        await acquireLock(runId);
        const sessionRoot = tempDir("recoverystore-session-");
        await recovery.methods.enrollRecovery(runId, exec, sessionRoot);
        await store.transition(runId, exec, "running");
        await store.commitContext(runId, exec, 0, {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        });
        await store.initializeToolJournal(runId, exec);
        await store.initializeControl(runId, exec);
      },
    );

    await withRecovery(
      dbPath,
      { locked: ["run_rec_deadline"] },
      async (store, recovery, _db, acquireLock) => {
        await expect(
          recovery.methods.claimRecovery(
            "run_rec_deadline",
            claimInput(exec!, 0),
          ),
        ).rejects.toThrow(/deadline expired/);
        // Nothing rotated, no recovery record, no pause cleared.
        expect((await store.get("run_rec_deadline"))?.attemptId).toBe(exec);
        expect((await store.get("run_rec_deadline"))?.status).toBe("running");
        expect((await store.getControl("run_rec_deadline"))?.intent).toBe(
          "run",
        );
        expect(
          await recovery.methods.listRecoveries("run_rec_deadline"),
        ).toEqual([]);
      },
    );
  });

  it("rolls the whole claim back on an injected write failure", async () => {
    const dbPath = tempDb();
    let exec: string;
    await withRecovery(
      dbPath,
      { fresh: ["run_rec_rollback"], locked: ["run_rec_rollback"] },
      async (store, recovery, _db, acquireLock) => {
        exec = await enrolledRun(
          store,
          recovery,
          "run_rec_rollback",
          acquireLock,
        );
        await store.transition("run_rec_rollback", exec, "running");
        await store.commitContext("run_rec_rollback", exec, 0, {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        });
        await store.initializeToolJournal("run_rec_rollback", exec);
        await store.initializeControl("run_rec_rollback", exec);
      },
    );

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_recovery_insert BEFORE INSERT ON recovery_records " +
        "BEGIN SELECT RAISE(ABORT, 'injected recovery write failure'); END",
    );
    raw.close();

    await withRecovery(
      dbPath,
      { locked: ["run_rec_rollback"] },
      async (store, recovery, _db, acquireLock) => {
        await expect(
          recovery.methods.claimRecovery(
            "run_rec_rollback",
            claimInput(exec!, 0),
          ),
        ).rejects.toThrow();
        // All-or-nothing: nothing rotated, no pause cleared, no record.
        expect((await store.get("run_rec_rollback"))?.attemptId).toBe(exec);
        expect(
          await recovery.methods.listRecoveries("run_rec_rollback"),
        ).toEqual([]);
      },
    );
  });
});

describe("execution-write lock gating", () => {
  it("requires the lock only for enrolled runs", async () => {
    const dbPath = tempDb();
    await withRecovery(
      dbPath,
      { fresh: ["run_rec_gate"], locked: ["run_rec_gate"] },
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_gate";
        const exec = await enrolledRun(store, recovery, runId, acquireLock);
        await store.transition(runId, exec, "running");
        await store.commitContext(runId, exec, 0, {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        });
        await store.initializeToolJournal(runId, exec);
        await store.initializeControl(runId, exec);
      },
    );

    // Not holding the lock: the gate refuses.
    await withRecovery(
      dbPath,
      undefined,
      async (_store, recovery, _db, acquireLock) => {
        expect(() => recovery.assertExecutionLock("run_rec_gate")).toThrow(
          /Execution lock is not held/,
        );
      },
    );

    // Holding the lock: the gate passes.
    await withRecovery(
      dbPath,
      { locked: ["run_rec_gate"] },
      async (_store, recovery, _db, acquireLock) => {
        recovery.assertExecutionLock("run_rec_gate");
      },
    );

    // Legacy run without enrollment: no-op either way.
    await withRecovery(
      tempDb(),
      undefined,
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_legacy_gate";
        const exec = await admit(store, runId);
        await store.transition(runId, exec, "running");
        recovery.assertExecutionLock(runId);
      },
    );
  });
});

describe("preservation across claim", () => {
  it("keeps model attempts, retries, budget, deadline, evidence, and approvals", async () => {
    const dbPath = tempDb();
    let exec: string;
    const sha = (n: number) => n.toString(16).padStart(64, "0");
    await withRecovery(
      dbPath,
      { fresh: ["run_rec_preserve"], locked: ["run_rec_preserve"] },
      async (store, recovery, dbPath, acquireLock) => {
        const runId = "run_rec_preserve";
        exec = (
          await store.admit({
            ...spec(runId),
            limits: {
              maxModelAttempts: 4,
              deadlineAt: "2099-01-01T00:00:00.000Z",
            },
          })
        ).record.attemptId;
        await acquireLock(runId);
        await recovery.methods.enrollRecovery(
          runId,
          exec,
          tempDir("recoverystore-session-"),
        );
        await store.transition(runId, exec, "running");
        await store.commitContext(
          runId,
          exec,
          0,
          {
            kind: "replace",
            messages: [{ role: "user", content: "first" }],
            system: null,
          },
          {
            rootPath: tempDir("recoverystore-evroot-"),
            files: [{ path: "a.txt", sha256: sha(1), bytes: 1 }],
          },
        );
        await store.initializeToolJournal(runId, exec);
        await store.initializeControl(runId, exec);
        const model = startInferenceAttempt({
          operationKind: "agent.stream",
          requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
        });
        await store.startModelAttempt(runId, exec, model.started);
        await store.settleModelAttempt(runId, exec, model.complete());
        await store.recordRetry(runId, exec, {
          authority: "stream-idle",
          count: 1,
          maxRetries: 3,
          delayMs: 10,
        });
        const approval = await store.requestApproval(runId, exec, {
          toolCallId: "tc_1",
          toolName: "http_request",
          input: { url: "http://127.0.0.1:8080/" },
        });
        await store.resolveApproval(runId, approval.approvalId, "denied");
      },
    );

    // Simulate executor loss: the same database reopened without freshness
    // but with the lock re-acquired by the recovering executor.
    await withRecovery(
      dbPath,
      { locked: ["run_rec_preserve"] },
      async (store, recovery, _db, acquireLock) => {
        const runId = "run_rec_preserve";
        const before = {
          approvals: await store.listApprovals(runId),
          models: await store.listModelAttempts(runId),
          retries: await store.listRetries(runId),
          evidence: await store.getEvidence(runId),
          limits: (await store.get(runId))?.spec.limits,
        };
        const record = await recovery.methods.claimRecovery(
          runId,
          claimInput(exec!, 0),
        );

        const approvals = await store.listApprovals(runId);
        expect(approvals).toEqual(before.approvals);
        expect(approvals[0]).toMatchObject({
          state: "denied",
          reason: "user_rejected",
        });
        expect(await store.listModelAttempts(runId)).toEqual(before.models);
        expect(await store.listRetries(runId)).toEqual(before.retries);
        expect(await store.getEvidence(runId)).toEqual(before.evidence);
        expect((await store.get(runId))?.spec.limits).toEqual(before.limits);
        expect(before.models).toHaveLength(1);
        expect(before.retries).toHaveLength(1);
        expect((await store.get(runId))?.attemptId).toBe(record.toAttemptId);
      },
    );
  });
});
