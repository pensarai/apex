import { modelMessageSchema } from "ai";
import { z } from "zod";
import type { RunContextSnapshot, RunObservation } from "./runObservation";
import { RunRecordSchema } from "./runStore";

export const WORKER_PROTOCOL_VERSION = 1;

/** Validation failure for a malformed or incompatible peer message. */
export class LocalWorkerProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LocalWorkerProtocolError";
  }
}

const versioned = z.literal(WORKER_PROTOCOL_VERSION);

export const WorkerCursorSchema = z.strictObject({
  workerId: z.string().min(1),
  sequence: z.number().int().nonnegative(),
});

export const LocalWorkerRequestSchema = z.discriminatedUnion("method", [
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("snapshot"),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("watch"),
    cursor: WorkerCursorSchema.optional(),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("start"),
    spec: z.unknown(),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("resume"),
    expectedAttemptId: z.string().min(1),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("pause"),
    expectedRevision: z.number().int().nonnegative(),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("stop"),
    expectedRevision: z.number().int().nonnegative(),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("approve"),
    approvalId: z.string().min(1),
  }),
  z.strictObject({
    protocolVersion: versioned,
    method: z.literal("reject"),
    approvalId: z.string().min(1),
  }),
]);

export type LocalWorkerRequest = z.output<typeof LocalWorkerRequestSchema>;

const ContextSnapshotSchema = z.strictObject({
  epoch: z.number().int().positive(),
  revision: z.number().int().positive(),
  messages: z.array(modelMessageSchema),
  system: z.string().nullable(),
});

const ControlSnapshotSchema = z.strictObject({
  schemaVersion: z.literal(1),
  runId: z.string().min(1),
  executionAttemptId: z.string().min(1),
  intent: z.enum(["run", "pause", "stop"]),
  revision: z.number().int().nonnegative(),
  updatedAt: z.string().min(1),
});

const ApprovalSnapshotSchema = z.strictObject({
  schemaVersion: z.literal(1),
  approvalId: z.string().min(1),
  runId: z.string().min(1),
  executionAttemptId: z.string().min(1),
  toolCallId: z.string().min(1),
  toolName: z.string().min(1),
  input: z.unknown(),
  specDigest: z.string().min(1),
  context: z.strictObject({
    epoch: z.number().int().positive(),
    revision: z.number().int().positive(),
  }),
  state: z.enum(["pending", "approved", "denied"]),
  reason: z.enum(["user_rejected", "run_stopped"]).optional(),
  createdAt: z.string().min(1),
  decidedAt: z.string().min(1).optional(),
});

// Transport-shape validation only; the store stays the semantic authority.
export const RunObservationSchema = z.strictObject({
  record: RunRecordSchema.nullable(),
  context: ContextSnapshotSchema.nullable(),
  control: ControlSnapshotSchema.nullable(),
  approvals: z.array(ApprovalSnapshotSchema),
});

export const WorkerSnapshotSchema = z.strictObject({
  protocolVersion: versioned,
  workerId: z.string().min(1),
  runId: z.string().min(1),
  phase: z.enum(["idle", "executing", "settled"]),
  sequence: z.number().int().nonnegative(),
  observation: RunObservationSchema,
  error: z
    .strictObject({
      message: z.string().min(1),
      blockers: z.array(z.string()).optional(),
    })
    .optional(),
});

export type WorkerSnapshot = z.output<typeof WorkerSnapshotSchema>;

function mismatch(kind: string, value: unknown): LocalWorkerProtocolError {
  const found =
    typeof value === "object" && value !== null
      ? (value as { protocolVersion?: unknown }).protocolVersion
      : value;
  return new LocalWorkerProtocolError(
    `Incompatible worker ${kind}: protocolVersion ${String(found)} is not supported (expected ${WORKER_PROTOCOL_VERSION})`,
  );
}

/** Parse and validate an incoming worker request; clear on version drift. */
export function parseWorkerRequest(value: unknown): LocalWorkerRequest {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as { protocolVersion?: unknown }).protocolVersion !==
      WORKER_PROTOCOL_VERSION
  ) {
    throw mismatch("request", value);
  }
  const parsed = LocalWorkerRequestSchema.safeParse(value);
  if (!parsed.success) {
    throw new LocalWorkerProtocolError(
      `Malformed worker request: ${parsed.error.issues[0]?.message ?? "invalid shape"}`,
    );
  }
  return parsed.data;
}

/** Parse and validate a worker response; clear on version drift. */
export function parseWorkerSnapshot(value: unknown): WorkerSnapshot {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as { protocolVersion?: unknown }).protocolVersion !==
      WORKER_PROTOCOL_VERSION
  ) {
    throw mismatch("response", value);
  }
  const parsed = WorkerSnapshotSchema.safeParse(value);
  if (!parsed.success) {
    throw new LocalWorkerProtocolError(
      `Malformed worker response: ${parsed.error.issues[0]?.message ?? "invalid shape"}`,
    );
  }
  return parsed.data;
}

// Re-exported for consumers that hold observations without store types.
export type { RunContextSnapshot, RunObservation };
