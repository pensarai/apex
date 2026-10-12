import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { captureEnvironment } from "./localRunLock";
import type { ContextReference } from "./runContext";
import type { RunControlRecord } from "./runControlStore";
import { RunLimitError } from "./runModelStore";
import type {
  RecoveryEnrollment,
  RecoveryRecord,
  RunRecoveryStore,
} from "./runRecoveryStore";
import type { RunRecord } from "./runStore";

// Must stay in lockstep with the tool journal's schema version.
const JOURNAL_VERSION = 1;

export const RECOVERY_STORE_SCHEMA_SQL = `
  CREATE TABLE recovery_enrollments (
    run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(run_id),
    record_json TEXT NOT NULL
  );
  CREATE TABLE recovery_records (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    recovery_id TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(run_id, recovery_id)
  );
`;

const EXECUTION_ATTEMPT_PATTERN =
  /^exec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RUN_ID_PATTERN = /^run_[A-Za-z0-9_-]{1,62}$/;

const EnvironmentSchema = z
  .object({
    runtimeVersion: z.string().min(1),
    host: z.string().min(1),
    platform: z.string().min(1),
    arch: z.string().min(1),
    databasePath: z.string().min(1),
    databaseDev: z.number(),
    databaseIno: z.number(),
    cwdPath: z.string().min(1),
    cwdDev: z.number(),
    cwdIno: z.number(),
    sessionRootPath: z.string().min(1),
    sessionRootDev: z.number(),
    sessionRootIno: z.number(),
  })
  .strict();

const EnrollmentSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: z.string().regex(RUN_ID_PATTERN),
    protocol: z.literal(1),
    enrolledAt: z.iso.datetime(),
    executionAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
    environment: EnvironmentSchema,
  })
  .strict();

const ReconstructionSchema = z
  .object({
    sourceContext: z
      .object({
        epoch: z.number().int().positive(),
        revision: z.number().int().positive(),
      })
      .strict(),
    reconstructedToolCalls: z.array(
      z
        .object({
          toolCallId: z.string().min(1),
          operationId: z.string().min(1),
        })
        .strict(),
    ),
    restartedModelAttempts: z.array(z.string().min(1)),
    deniedToolCalls: z.array(z.string().min(1)),
    discardedUncommitted: z.boolean(),
  })
  .strict();

const ClaimInputSchema = z
  .object({
    expectedAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
    expectedContext: z
      .object({
        epoch: z.number().int().positive(),
        revision: z.number().int().positive(),
      })
      .strict(),
    expectedControlRevision: z.number().int().nonnegative(),
    reconstruction: ReconstructionSchema,
  })
  .strict();

const RecoveryRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    recoveryId: z.string().regex(/^rec_[0-9a-f-]{36}$/),
    runId: z.string().regex(RUN_ID_PATTERN),
    claimedAt: z.iso.datetime(),
    fromAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
    toAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
    fromContext: z
      .object({
        epoch: z.number().int().positive(),
        revision: z.number().int().positive(),
      })
      .strict(),
    input: ClaimInputSchema,
  })
  .strict();

interface RecoveryDatabase {
  prepare(sql: string): {
    get(...values: (string | number)[]): unknown;
    all(...values: (string | number)[]): unknown[];
    run(...values: (string | number)[]): unknown;
  };
}

type RecoveryMethods = Omit<RunRecoveryStore, "acquireExecutionLock">;

export function createSqliteRecoveryStore(input: {
  db: RecoveryDatabase;
  transaction<T>(operation: () => T): T;
  getRun(runId: string): RunRecord | undefined;
  getContextReference(runId: string): ContextReference | null;
  readControl(runId: string): RunControlRecord | undefined;
  databasePath: string;
  /** True only for attempts freshly admitted through this store instance. */
  isFreshAdmission(runId: string): boolean;
  /** True while this process holds the run's execution lock. */
  lockHeld(runId: string): boolean;
  runtimeVersion: string;
}): {
  methods: RecoveryMethods;
  /**
   * Synchronous lock gate for execution-write transactions: an enrolled run
   * must currently hold its execution lock; legacy runs (no enrollment) are
   * unaffected.
   */
  assertExecutionLock(runId: string): void;
} {
  const { db, transaction } = input;

  const readEnrollment = (runId: string): RecoveryEnrollment | undefined => {
    const row = db
      .prepare("SELECT record_json FROM recovery_enrollments WHERE run_id = ?")
      .get(runId);
    if (row == null) return undefined;
    const enrollment = EnrollmentSchema.parse(
      JSON.parse((row as { record_json: string }).record_json),
    );
    if (enrollment.runId !== runId) {
      throw new Error("Recovery enrollment identity is corrupt");
    }
    return enrollment;
  };

  const writeRunOwner = (runId: string, record: RunRecord, at: string) => {
    db.prepare("UPDATE runs SET record_json = ? WHERE run_id = ?").run(
      JSON.stringify({ ...record, updatedAt: at }),
      runId,
    );
  };

  const methods: RecoveryMethods = {
    async enrollRecovery(runId, executionAttemptId, sessionRoot) {
      // Every mutation path — including the idempotent read of an existing
      // enrollment — requires the lock both before awaits and inside the
      // transaction, so a released lock can never leave an enrollment behind.
      if (!input.lockHeld(runId)) {
        throw new Error(`Execution lock is not held for run ${runId}`);
      }
      const run = input.getRun(runId);
      if (!run || run.attemptId !== executionAttemptId) {
        throw new Error("Execution attempt does not own this run");
      }
      // Admitted/running alone does not prove freshness — only this store
      // instance's fresh admission does. Old crashed runs never enroll.
      if (!input.isFreshAdmission(runId)) {
        throw new Error(
          "Run was not freshly admitted through this store; enrollment refused",
        );
      }
      if (!["admitted", "running"].includes(run.status)) {
        throw new Error("Run is not enrollable");
      }
      const existing = readEnrollment(runId);
      if (existing) {
        if (existing.executionAttemptId !== executionAttemptId) {
          throw new Error(
            "Recovery enrollment is owned by another execution attempt",
          );
        }
        return existing;
      }
      const environment = await captureEnvironment({
        databasePath: input.databasePath,
        cwdPath: run.spec.environment.cwd,
        sessionRoot,
        runtimeVersion: input.runtimeVersion,
      });
      const enrollment: RecoveryEnrollment = {
        schemaVersion: 1,
        runId,
        protocol: 1,
        enrolledAt: new Date().toISOString(),
        executionAttemptId,
        environment,
      };
      transaction(() => {
        if (!input.lockHeld(runId)) {
          throw new Error(`Execution lock is not held for run ${runId}`);
        }
        const current = input.getRun(runId);
        if (!current || current.attemptId !== executionAttemptId) {
          throw new Error("Execution attempt does not own this run");
        }
        if (!input.isFreshAdmission(runId)) {
          throw new Error(
            "Run was not freshly admitted through this store; enrollment refused",
          );
        }
        if (readEnrollment(runId)) {
          throw new Error("Recovery enrollment already exists");
        }
        db.prepare(
          "INSERT INTO recovery_enrollments (run_id, record_json) VALUES (?, ?)",
        ).run(runId, JSON.stringify(EnrollmentSchema.parse(enrollment)));
      });
      return enrollment;
    },
    async getRecoveryEnrollment(runId) {
      return readEnrollment(runId);
    },
    async claimRecovery(runId, candidate) {
      const claim = ClaimInputSchema.parse(candidate);
      // Unenrolled legacy runs refuse on enrollment, not the lock — matching
      // the public gate, which only applies to enrolled runs.
      const preEnrollment = readEnrollment(runId);
      if (!preEnrollment) {
        throw new Error("Run has no recovery enrollment; cannot resume");
      }
      if (!input.lockHeld(runId)) {
        throw new Error(`Execution lock is not held for run ${runId}`);
      }
      // Filesystem identity is captured BEFORE the transaction: the store's
      // transaction helper is synchronous, so the body must not await.
      const preRun = input.getRun(runId);
      if (!preRun) throw new Error("Run does not exist");
      const currentEnvironment = await captureEnvironment({
        databasePath: input.databasePath,
        cwdPath: preRun.spec.environment.cwd,
        sessionRoot: preEnrollment.environment.sessionRootPath,
        runtimeVersion: input.runtimeVersion,
      });
      const record = await transaction(() => {
        if (!input.lockHeld(runId)) {
          throw new Error(`Execution lock is not held for run ${runId}`);
        }
        const run = input.getRun(runId);
        if (!run) throw new Error("Run does not exist");
        const enrollment = readEnrollment(runId);
        if (!enrollment) {
          throw new Error("Run has no recovery enrollment; cannot resume");
        }
        if (enrollment.executionAttemptId !== claim.expectedAttemptId) {
          throw new Error("Recovery enrollment owner changed");
        }
        if (run.attemptId !== claim.expectedAttemptId) {
          throw new Error("Execution attempt does not own this run");
        }
        if (!["running", "paused", "failed"].includes(run.status)) {
          throw new Error(`Run status ${run.status} cannot be recovered`);
        }
        const context = input.getContextReference(runId);
        if (
          !context ||
          context.epoch !== claim.expectedContext.epoch ||
          context.revision !== claim.expectedContext.revision
        ) {
          throw new Error("Context revision conflict");
        }
        if (
          claim.reconstruction.sourceContext.epoch !== context.epoch ||
          claim.reconstruction.sourceContext.revision !== context.revision
        ) {
          throw new Error("Reconstruction does not match the current context");
        }
        const control = input.readControl(runId);
        if (!control)
          throw new Error("Control is not initialized for this run");
        if (control.executionAttemptId !== claim.expectedAttemptId) {
          throw new Error("Control is enrolled by another execution attempt");
        }
        if (control.revision !== claim.expectedControlRevision) {
          throw new Error("Control revision conflict");
        }
        if (control.intent === "stop") {
          throw new Error("Run stop was requested; recovery is refused");
        }
        // Recheck inside the transaction: the async preflight (filesystem
        // capture) may cross the absolute deadline after the gate check.
        const deadlineAt = run.spec.limits?.deadlineAt;
        if (deadlineAt && Date.now() >= Date.parse(deadlineAt)) {
          throw new RunLimitError("Recorded run deadline expired");
        }

        // Environment must still match the enrolled identity — a moved or
        // copied database, or a changed cwd/session root, blocks.
        if (!isDeepStrictEqual(currentEnvironment, enrollment.environment)) {
          throw new Error(
            "Run environment changed since enrollment; recovery is refused",
          );
        }

        const journalRow = db
          .prepare(
            "SELECT version, execution_attempt_id FROM tool_journals WHERE run_id = ?",
          )
          .get(runId) as
          | { version: number; execution_attempt_id: string }
          | undefined;
        if (!journalRow) {
          throw new Error("Tool journal is not initialized for this run");
        }
        if (journalRow.version !== JOURNAL_VERSION) {
          throw new Error(
            `Tool journal version ${journalRow.version} is not supported`,
          );
        }
        if (journalRow.execution_attempt_id !== claim.expectedAttemptId) {
          throw new Error(
            "Tool journal is enrolled by another execution attempt",
          );
        }

        const now = new Date().toISOString();
        const newAttemptId = `exec_${randomUUID()}`;

        // Paused/failed cannot pass the ordinary transition lattice; the
        // grant sets running atomically with the new owner.
        writeRunOwner(
          runId,
          { ...run, attemptId: newAttemptId, status: "running" },
          now,
        );
        db.prepare(
          "UPDATE tool_journals SET execution_attempt_id = ? WHERE run_id = ?",
        ).run(newAttemptId, runId);
        db.prepare(
          "UPDATE run_controls SET record_json = ? WHERE run_id = ?",
        ).run(
          JSON.stringify({
            ...control,
            executionAttemptId: newAttemptId,
            // Pause clears to run for the recovering attempt; stop was
            // already refused above.
            intent: "run",
            revision: control.revision + 1,
            updatedAt: now,
          }),
          runId,
        );
        db.prepare(
          "UPDATE recovery_enrollments SET record_json = ? WHERE run_id = ?",
        ).run(
          JSON.stringify({
            ...enrollment,
            executionAttemptId: newAttemptId,
          }),
          runId,
        );

        const recovery: RecoveryRecord = {
          schemaVersion: 1,
          recoveryId: `rec_${randomUUID()}`,
          runId,
          claimedAt: now,
          fromAttemptId: claim.expectedAttemptId,
          toAttemptId: newAttemptId,
          fromContext: claim.expectedContext,
          input: claim,
        };
        db.prepare(
          "INSERT INTO recovery_records (run_id, recovery_id, claimed_at, record_json) VALUES (?, ?, ?, ?)",
        ).run(
          runId,
          recovery.recoveryId,
          recovery.claimedAt,
          JSON.stringify(RecoveryRecordSchema.parse(recovery)),
        );
        return recovery;
      });
      return record;
    },
    async listRecoveries(runId) {
      return db
        .prepare(
          "SELECT recovery_id, record_json FROM recovery_records WHERE run_id = ? ORDER BY claimed_at, rowid",
        )
        .all(runId)
        .map((row) => {
          const parsed = row as { recovery_id: string; record_json: string };
          const record = RecoveryRecordSchema.parse(
            JSON.parse(parsed.record_json),
          );
          if (
            record.recoveryId !== parsed.recovery_id ||
            record.runId !== runId
          ) {
            throw new Error("Recovery record identity is corrupt");
          }
          return record;
        });
    },
  };

  const assertExecutionLock = (runId: string): void => {
    // Legacy runs carry no enrollment and stay lock-free, exactly as before.
    if (readEnrollment(runId) === undefined) return;
    if (!input.lockHeld(runId)) {
      throw new Error(`Execution lock is not held for run ${runId}`);
    }
  };

  return { methods, assertExecutionLock };
}
