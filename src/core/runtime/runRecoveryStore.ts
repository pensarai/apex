/** Environment identity captured from the actual filesystem at enrollment. */
export interface RecoveryEnvironment {
  runtimeVersion: string;
  host: string;
  platform: string;
  arch: string;
  databasePath: string;
  databaseDev: number;
  databaseIno: number;
  cwdPath: string;
  cwdDev: number;
  cwdIno: number;
  sessionRootPath: string;
  sessionRootDev: number;
  sessionRootIno: number;
}

export interface RecoveryEnrollment {
  schemaVersion: 1;
  runId: string;
  protocol: 1;
  enrolledAt: string;
  executionAttemptId: string;
  environment: RecoveryEnvironment;
}

export interface RecoveryReconstructionSummary {
  sourceContext: { epoch: number; revision: number };
  /** Tool calls whose settled effects were reconstructed into context. */
  reconstructedToolCalls: Array<{ toolCallId: string; operationId: string }>;
  /** Model attempts accepted as safely restartable (zero accepted effects). */
  restartedModelAttempts: string[];
  /** Denied approvals reconstructed as blocked tool results. */
  deniedToolCalls: string[];
  discardedUncommitted: boolean;
}

export interface RecoveryClaimInput {
  expectedAttemptId: string;
  expectedContext: { epoch: number; revision: number };
  expectedControlRevision: number;
  reconstruction: RecoveryReconstructionSummary;
}

export interface RecoveryRecord {
  schemaVersion: 1;
  recoveryId: string;
  runId: string;
  claimedAt: string;
  fromAttemptId: string;
  toAttemptId: string;
  fromContext: { epoch: number; revision: number };
  input: RecoveryClaimInput;
}

/** Local execution exclusion and auditable ownership changes. */
export interface RunRecoveryStore {
  acquireExecutionLock(runId: string): Promise<ExecutionLock>;
  /** Requires a held lock and a fresh admission through this store instance. */
  enrollRecovery(
    runId: string,
    executionAttemptId: string,
    sessionRoot: string,
  ): Promise<RecoveryEnrollment>;
  getRecoveryEnrollment(runId: string): Promise<RecoveryEnrollment | undefined>;
  /** Rotate owners atomically after checking the expected context and control revisions. */
  claimRecovery(
    runId: string,
    input: RecoveryClaimInput,
  ): Promise<RecoveryRecord>;
  listRecoveries(runId: string): Promise<RecoveryRecord[]>;
}

export interface ExecutionLock {
  readonly runId: string;
  /** Release = close the dedicated connection. Idempotent; never throws. */
  release(): void;
}
