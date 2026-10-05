import { createHash, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import type { ContextReference } from "./runContext";
import {
  type RecordedApproval,
  RunControlConflictError,
  RunControlInterruption,
  type RunControlRecord,
  type RunControlStore,
} from "./runControlStore";
import type { RunRecord } from "./runStore";

export const CONTROL_STORE_SCHEMA_SQL = `
  CREATE TABLE run_controls (
    run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(run_id),
    record_json TEXT NOT NULL
  );
  CREATE TABLE tool_approvals (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    approval_id TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(run_id, approval_id),
    UNIQUE(run_id, tool_call_id)
  );
`;

const EXECUTION_ATTEMPT_PATTERN =
  /^exec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const APPROVAL_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SPEC_DIGEST_PATTERN = /^[a-f0-9]{64}$/;

const ControlRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: z.string().min(1),
    executionAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
    intent: z.enum(["run", "pause", "stop"]),
    revision: z.number().int().nonnegative(),
    updatedAt: z.iso.datetime(),
  })
  .strict();

// State-dependent shape: resolved records carry their decision timestamp,
// denials carry the fixed reason, pending carries neither.
const approvalCommonShape = {
  schemaVersion: z.literal(1),
  approvalId: z.string().regex(APPROVAL_ID_PATTERN),
  runId: z.string().min(1),
  executionAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
  toolCallId: z.string().min(1),
  toolName: z.string().min(1),
  input: z.custom<unknown>((value) => value !== undefined),
  specDigest: z.string().regex(SPEC_DIGEST_PATTERN),
  context: z
    .object({
      epoch: z.number().int().positive(),
      revision: z.number().int().positive(),
    })
    .strict(),
  createdAt: z.iso.datetime(),
};

const ApprovalRecordSchema = z.discriminatedUnion("state", [
  z.object({ ...approvalCommonShape, state: z.literal("pending") }).strict(),
  z
    .object({
      ...approvalCommonShape,
      state: z.literal("approved"),
      decidedAt: z.iso.datetime(),
    })
    .strict(),
  z
    .object({
      ...approvalCommonShape,
      state: z.literal("denied"),
      decidedAt: z.iso.datetime(),
      reason: z.enum(["user_rejected", "run_stopped"]),
    })
    .strict(),
]);

interface ControlDatabase {
  prepare(sql: string): {
    get(...values: (string | number)[]): unknown;
    all(...values: (string | number)[]): unknown[];
    run(...values: (string | number)[]): unknown;
  };
}

/** The persisted form is the only input ever stored — a value JSON cannot round-trip exactly is rejected. */
function durableInput(input: unknown): unknown {
  const serialized = JSON.stringify(input);
  const roundTrip = JSON.parse(serialized);
  if (!isDeepStrictEqual(roundTrip, input)) {
    throw new Error("Approval input is not completely JSON-serializable");
  }
  return roundTrip;
}

export function createSqliteControlStore(input: {
  db: ControlDatabase;
  transaction<T>(operation: () => T): T;
  getRun(runId: string): RunRecord | undefined;
  assertExecutionLock?(runId: string): void;
  getContextReference(runId: string): ContextReference | null;
}): {
  methods: RunControlStore;
  /**
   * Synchronous read of the enrolled control record: lets status-write
   * transactions atomically honor stop dominance and paused eligibility.
   */
  readControl(runId: string): RunControlRecord | undefined;
  /**
   * Synchronous, no transaction of its own: called inside model/tool start
   * transactions. Validates the control owner; absent enrollment allows
   * dispatch only for specs that require no approvals.
   */
  assertDispatchAllowed(runId: string): void;
  /**
   * Synchronous gate called inside the tool-intent transaction with C1's
   * accepted identity: dispatch must be allowed, the tool must be admitted,
   * and gated tools need an approved record matching the toolCallId, tool
   * name, exact input, owner attempt, and admitted spec digest.
   */
  assertToolApproved(
    runId: string,
    toolName: string,
    toolCallId: string,
    candidateInput: unknown,
  ): void;
} {
  const { db, transaction } = input;

  const readControl = (runId: string) => {
    const row = db
      .prepare("SELECT record_json FROM run_controls WHERE run_id = ?")
      .get(runId);
    // bun:sqlite returns null for no row, node:sqlite undefined — nullish
    // absence is the only portable check.
    if (row == null) return undefined;
    const record = ControlRecordSchema.parse(
      JSON.parse((row as { record_json: string }).record_json),
    );
    if (record.runId !== runId) {
      throw new Error("Control record identity is corrupt");
    }
    return record;
  };

  const writeControl = (record: z.infer<typeof ControlRecordSchema>) => {
    db.prepare(
      "INSERT INTO run_controls (run_id, record_json) VALUES (?, ?) " +
        "ON CONFLICT(run_id) DO UPDATE SET record_json = excluded.record_json",
    ).run(record.runId, JSON.stringify(ControlRecordSchema.parse(record)));
  };

  const readApprovalRow = (runId: string, approvalId: string) => {
    const row = db
      .prepare(
        "SELECT approval_id, tool_call_id, record_json FROM tool_approvals WHERE run_id = ? AND approval_id = ?",
      )
      .get(runId, approvalId);
    if (row == null) return undefined;
    const parsed = row as {
      approval_id: string;
      tool_call_id: string;
      record_json: string;
    };
    const record = ApprovalRecordSchema.parse(JSON.parse(parsed.record_json));
    if (
      record.runId !== runId ||
      record.approvalId !== parsed.approval_id ||
      record.toolCallId !== parsed.tool_call_id
    ) {
      throw new Error("Approval record identity is corrupt");
    }
    return record;
  };

  const writeApproval = (record: RecordedApproval) => {
    db.prepare(
      "UPDATE tool_approvals SET record_json = ? WHERE run_id = ? AND approval_id = ?",
    ).run(
      JSON.stringify(ApprovalRecordSchema.parse(record)),
      record.runId,
      record.approvalId,
    );
  };

  const readApprovals = (runId: string) => {
    const rows = db
      .prepare(
        "SELECT approval_id, tool_call_id, record_json FROM tool_approvals WHERE run_id = ? ORDER BY rowid",
      )
      .all(runId) as Array<{
      approval_id: string;
      tool_call_id: string;
      record_json: string;
    }>;
    return rows.map((row) => {
      const record = ApprovalRecordSchema.parse(JSON.parse(row.record_json));
      if (
        record.runId !== runId ||
        record.approvalId !== row.approval_id ||
        record.toolCallId !== row.tool_call_id
      ) {
        throw new Error("Approval record identity is corrupt");
      }
      return record;
    });
  };

  const denyPending = (runId: string, reason: "run_stopped", at: string) => {
    const denied: RecordedApproval[] = [];
    for (const record of readApprovals(runId)) {
      if (record.state !== "pending") continue;
      const resolved: RecordedApproval = {
        ...record,
        state: "denied",
        reason,
        decidedAt: at,
      };
      writeApproval(resolved);
      denied.push(resolved);
    }
    return denied;
  };

  const enrolledControl = (runId: string, executionAttemptId: string) => {
    const run = input.getRun(runId);
    if (!run || run.attemptId !== executionAttemptId) {
      throw new Error("Execution attempt does not own this run");
    }
    if (run.status !== "running") throw new Error("Run is not running");
    const control = readControl(runId);
    if (!control) throw new Error("Control is not initialized for this run");
    if (control.executionAttemptId !== executionAttemptId) {
      throw new Error("Control is enrolled by another execution attempt");
    }
    return { run, control };
  };

  const specDigest = (run: RunRecord) =>
    createHash("sha256").update(JSON.stringify(run.spec)).digest("hex");

  const methods: RunControlStore = {
    async initializeControl(runId, executionAttemptId) {
      transaction(() => {
        input.assertExecutionLock?.(runId);
        const run = input.getRun(runId);
        if (!run || run.attemptId !== executionAttemptId) {
          throw new Error("Execution attempt does not own this run");
        }
        // Admitted is enrollable so a pre-aborted run can persist stop
        // before session creation; terminal statuses never enroll.
        if (!["admitted", "running"].includes(run.status)) {
          throw new Error("Run is not enrollable");
        }
        const control = readControl(runId);
        if (control) {
          if (control.executionAttemptId !== executionAttemptId) {
            throw new Error("Control is enrolled by another execution attempt");
          }
          return;
        }
        writeControl({
          schemaVersion: 1,
          runId,
          executionAttemptId,
          intent: "run",
          revision: 0,
          updatedAt: new Date().toISOString(),
        });
      });
    },
    async getControl(runId) {
      return readControl(runId);
    },
    async requestControl(runId, intent, expectedRevision) {
      // Client input, not a trusted in-process caller: validate the command
      // shape before touching the record.
      const commandIntent = z.enum(["pause", "stop"]).parse(intent);
      const revision = z.number().int().nonnegative().parse(expectedRevision);
      return transaction(() => {
        const run = input.getRun(runId);
        if (!run) throw new Error("Run does not exist");
        const control = readControl(runId);
        if (!control)
          throw new Error("Control is not initialized for this run");
        if (control.executionAttemptId !== run.attemptId) {
          throw new Error("Control is enrolled by another execution attempt");
        }
        if (control.revision !== revision) {
          throw new RunControlConflictError("Control revision conflict");
        }
        // An identical replay is a read, not a mutation — terminal runs keep it.
        if (control.intent === commandIntent) return control;
        if (["completed", "failed", "cancelled"].includes(run.status)) {
          throw new Error("Run is terminal; control mutations are rejected");
        }
        if (control.intent === "stop") {
          throw new Error("Stop dominates; pause cannot clear stop");
        }
        const updatedAt = new Date().toISOString();
        const next = {
          ...control,
          intent: commandIntent,
          revision: control.revision + 1,
          updatedAt,
        };
        writeControl(next);
        if (commandIntent === "stop") {
          denyPending(runId, "run_stopped", updatedAt);
        }
        return next;
      });
    },
    async requestApproval(runId, executionAttemptId, request) {
      const toolCallId = z.string().min(1).parse(request.toolCallId);
      const toolName = z.string().min(1).parse(request.toolName);
      const candidate = durableInput(request.input);
      return transaction(() => {
        input.assertExecutionLock?.(runId);
        const { run, control } = enrolledControl(runId, executionAttemptId);
        assertDispatchAllowed(runId);
        if (!run.spec.activeTools.some((name) => name === toolName)) {
          throw new Error(
            `Tool is not in the run's active tool allowlist: ${toolName}`,
          );
        }
        const context = input.getContextReference(runId);
        if (!context) {
          throw new Error("Approval requires a committed context");
        }
        const existingRow = db
          .prepare(
            "SELECT approval_id, tool_call_id, record_json FROM tool_approvals WHERE run_id = ? AND tool_call_id = ?",
          )
          .get(runId, toolCallId);
        if (existingRow != null) {
          const parsed = existingRow as {
            approval_id: string;
            tool_call_id: string;
            record_json: string;
          };
          const existing = ApprovalRecordSchema.parse(
            JSON.parse(parsed.record_json),
          );
          if (
            existing.runId !== runId ||
            existing.approvalId !== parsed.approval_id ||
            existing.toolCallId !== parsed.tool_call_id
          ) {
            throw new Error("Approval record identity is corrupt");
          }
          if (
            existing.executionAttemptId !== executionAttemptId ||
            existing.specDigest !== specDigest(run) ||
            existing.toolName !== toolName ||
            !isDeepStrictEqual(existing.input, candidate)
          ) {
            throw new Error(
              "Approval was already requested with different tool identity or input",
            );
          }
          return existing;
        }
        const record: RecordedApproval = {
          schemaVersion: 1,
          approvalId: randomUUID(),
          runId,
          executionAttemptId: control.executionAttemptId,
          toolCallId,
          toolName,
          input: candidate,
          specDigest: specDigest(run),
          context,
          state: "pending",
          createdAt: new Date().toISOString(),
        };
        db.prepare(
          "INSERT INTO tool_approvals (run_id, approval_id, tool_call_id, record_json) VALUES (?, ?, ?, ?)",
        ).run(
          runId,
          record.approvalId,
          toolCallId,
          JSON.stringify(ApprovalRecordSchema.parse(record)),
        );
        return record;
      });
    },
    async getApproval(runId, approvalId) {
      return readApprovalRow(runId, approvalId);
    },
    async listApprovals(runId) {
      return readApprovals(runId);
    },
    async resolveApproval(runId, approvalId, decision) {
      decision = z.enum(["approved", "denied"]).parse(decision);
      return transaction(() => {
        const control = readControl(runId);
        if (!control)
          throw new Error("Control is not initialized for this run");
        const record = readApprovalRow(runId, approvalId);
        if (!record) throw new Error("Approval does not exist");
        if (record.state !== "pending") {
          if (record.state === decision) return record;
          throw new Error(
            "Approval was already resolved with a different decision",
          );
        }
        const run = input.getRun(runId);
        if (
          !run ||
          control.executionAttemptId !== run.attemptId ||
          record.executionAttemptId !== run.attemptId ||
          record.specDigest !== specDigest(run)
        ) {
          throw new Error("Approval owner or admitted spec changed");
        }
        if (decision === "approved") {
          if (control.intent === "stop" || run.status !== "running") {
            throw new Error("Stopped or terminal runs cannot approve");
          }
          const resolved: RecordedApproval = {
            ...record,
            state: "approved",
            decidedAt: new Date().toISOString(),
          };
          writeApproval(resolved);
          return resolved;
        }
        const denied: RecordedApproval = {
          ...record,
          state: "denied",
          reason: "user_rejected",
          decidedAt: new Date().toISOString(),
        };
        writeApproval(denied);
        return denied;
      });
    },
  };

  const assertDispatchAllowed = (runId: string): void => {
    const run = input.getRun(runId);
    if (!run) throw new Error("Run does not exist");
    const required = run.spec.approval?.requiredTools ?? [];
    const control = readControl(runId);
    if (!control) {
      // Ungated legacy specs keep today's behavior; a spec requiring
      // approvals must never execute without enrollment.
      if (required.length > 0) {
        throw new Error(
          "Control is not initialized for a run whose spec requires approvals",
        );
      }
      return;
    }
    if (control.executionAttemptId !== run.attemptId) {
      throw new Error("Control is enrolled by another execution attempt");
    }
    if (control.intent === "stop") {
      throw new RunControlInterruption(
        "Run stop was requested; dispatch blocked",
      );
    }
    if (control.intent === "pause") {
      throw new RunControlInterruption(
        "Run pause was requested; no new dispatch until resumed",
      );
    }
  };

  const assertToolApproved = (
    runId: string,
    toolName: string,
    toolCallId: string,
    candidateInput: unknown,
  ): void => {
    // C1 accepted intent carries only the toolCallId; the approval UUID is
    // the client's resolve identifier.
    assertDispatchAllowed(runId);
    const run = input.getRun(runId)!;
    if (!run.spec.activeTools.some((name) => name === toolName)) {
      throw new Error(
        `Tool is not in the run's active tool allowlist: ${toolName}`,
      );
    }
    const required = run.spec.approval?.requiredTools ?? [];
    if (!required.some((name) => name === toolName)) return;
    const control = readControl(runId)!;
    const row = db
      .prepare(
        "SELECT approval_id, tool_call_id, record_json FROM tool_approvals WHERE run_id = ? AND tool_call_id = ?",
      )
      .get(runId, toolCallId);
    if (row == null) {
      throw new RunControlInterruption(
        "No approval record exists for a required tool call",
      );
    }
    const parsed = row as {
      approval_id: string;
      tool_call_id: string;
      record_json: string;
    };
    const record = ApprovalRecordSchema.parse(JSON.parse(parsed.record_json));
    if (
      record.runId !== runId ||
      record.approvalId !== parsed.approval_id ||
      record.toolCallId !== parsed.tool_call_id
    ) {
      throw new Error("Approval record identity is corrupt");
    }
    if (record.state !== "approved") {
      throw new RunControlInterruption(
        `Tool approval is ${record.state}; dispatch blocked`,
      );
    }
    if (record.toolName !== toolName) {
      throw new RunControlInterruption(
        "Approval was granted for a different tool",
      );
    }
    if (record.executionAttemptId !== control.executionAttemptId) {
      throw new RunControlInterruption(
        "Approval belongs to another execution attempt",
      );
    }
    if (!isDeepStrictEqual(record.input, candidateInput)) {
      throw new RunControlInterruption(
        "Approval was granted for different input",
      );
    }
    if (record.specDigest !== specDigest(run)) {
      throw new RunControlInterruption(
        "Approval was granted against a different admitted spec",
      );
    }
  };

  return { methods, readControl, assertDispatchAllowed, assertToolApproved };
}
