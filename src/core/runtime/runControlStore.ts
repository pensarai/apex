import type { ContextReference } from "./runContext";

export type RunControlIntent = "run" | "pause" | "stop";
export type ApprovalDecision = "approved" | "denied";

/** Durable control state for one recorded run, enrolled by its executor. */
export interface RunControlRecord {
  schemaVersion: 1;
  runId: string;
  executionAttemptId: string;
  intent: RunControlIntent;
  /** CAS token for commands; starts at 0 on enrollment. */
  revision: number;
  updatedAt: string;
}

/**
 * One pending or resolved operator approval. The record binds the exact
 * validated input and the admitted spec digest, so a decision can never
 * authorize different bytes. Unique per run and toolCallId; resolved once.
 */
export interface RecordedApproval {
  schemaVersion: 1;
  approvalId: string;
  runId: string;
  executionAttemptId: string;
  toolCallId: string;
  toolName: string;
  input: unknown;
  specDigest: string;
  context: ContextReference;
  state: "pending" | "approved" | "denied";
  reason?: "user_rejected" | "run_stopped";
  createdAt: string;
  decidedAt?: string;
}

export interface RunControlStore {
  /**
   * Executor-side enrollment immediately after admission; admitted or
   * running only, so a pre-aborted run can persist stop before session
   * creation. Idempotent per owner; terminal runs never enroll.
   */
  initializeControl(runId: string, executionAttemptId: string): Promise<void>;
  /** Read-only; works on terminal records; undefined when never enrolled. */
  getControl(runId: string): Promise<RunControlRecord | undefined>;
  /**
   * Client-side command with revision CAS. Identical intent is idempotent;
   * stop dominates (a pause after stop rejects) and denies every pending
   * approval (reason `run_stopped`) in the same transaction.
   */
  requestControl(
    runId: string,
    intent: "pause" | "stop",
    expectedRevision: number,
  ): Promise<RunControlRecord>;
  /**
   * Executor-side approval request bound to (toolCallId, validated input,
   * spec digest, context). Identical repeat returns the saved record; a
   * changed toolName or input rejects.
   */
  requestApproval(
    runId: string,
    executionAttemptId: string,
    request: { toolCallId: string; toolName: string; input: unknown },
  ): Promise<RecordedApproval>;
  getApproval(
    runId: string,
    approvalId: string,
  ): Promise<RecordedApproval | undefined>;
  listApprovals(runId: string): Promise<RecordedApproval[]>;
  /**
   * Resolve-once CAS: pending → approved|denied. Identical decision is
   * idempotent; a conflicting decision rejects. Approving requires the run
   * to be running. Denials record `user_rejected`.
   */
  resolveApproval(
    runId: string,
    approvalId: string,
    decision: ApprovalDecision,
  ): Promise<RecordedApproval>;
}

/**
 * CAS conflict on a control command's expected revision. Retryable by
 * re-reading the control record and re-issuing — never conflate with
 * storage failures, which must not be blindly retried.
 */
export class RunControlConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunControlConflictError";
  }
}

/**
 * Nonretryable control interruption (pause/stop, denied or unapproved
 * gate). Never subclasses storage failure — latched persistence errors and
 * operator intent are distinct failure classes.
 */
export class RunControlInterruption extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunControlInterruption";
  }
}
