import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { InferenceAttemptSchema, parseInferenceAttempt } from "../ai";
import type { ContextReference } from "./runContext";
import {
  type RecordedModelAttempt,
  RunLimitError,
  type RunModelStore,
} from "./runModelStore";
import type { RunRecord } from "./runStore";

export const MODEL_STORE_SCHEMA_SQL = `
  CREATE TABLE model_attempts (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    attempt_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(run_id, attempt_id)
  );
  CREATE TABLE model_retries (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    sequence INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(run_id, sequence)
  );
`;

const ToolCallSchema = z
  .object({ toolCallId: z.string().min(1), toolName: z.string().min(1) })
  .strict();
const ModelRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    attempt: InferenceAttemptSchema,
    context: z
      .object({
        epoch: z.number().int().positive(),
        revision: z.number().int().positive(),
      })
      .strict()
      .nullable(),
    toolCalls: z.array(ToolCallSchema),
    startedAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
  })
  .strict();
const RetryDecisionSchema = z
  .object({
    authority: z.enum([
      "stream-rate-limit",
      "stream-idle",
      "object-rate-limit",
      "context-restart",
    ]),
    count: z.number().int().positive(),
    maxRetries: z.number().int().nonnegative(),
    delayMs: z.number().int().nonnegative().max(86_400_000),
  })
  .strict()
  .refine((value) => value.count <= value.maxRetries);
const RetryRecordSchema = z
  .object({
    ...RetryDecisionSchema.shape,
    sequence: z.number().int().positive(),
    scheduledAt: z.iso.datetime(),
    dueAt: z.iso.datetime(),
  })
  .strict()
  .refine((value) => value.count <= value.maxRetries);

interface ModelDatabase {
  prepare(sql: string): {
    get(...values: (string | number)[]): unknown;
    all(...values: (string | number)[]): unknown[];
    run(...values: (string | number)[]): unknown;
  };
}

type ModelMethods = Pick<
  RunModelStore,
  | "startModelAttempt"
  | "observeModelToolCall"
  | "settleModelAttempt"
  | "recordRetry"
  | "listModelAttempts"
  | "listRetries"
>;

export function createSqliteModelStore(input: {
  db: ModelDatabase;
  transaction<T>(operation: () => T): T;
  getRun(runId: string): RunRecord | undefined;
  getContextReference(runId: string): ContextReference | null;
  assertDispatchAllowed?(runId: string): void;
}): ModelMethods {
  const { db, transaction } = input;
  const owningRun = (runId: string, executionAttemptId: string) => {
    const run = input.getRun(runId);
    if (!run || run.attemptId !== executionAttemptId)
      throw new Error("Execution attempt does not own this run");
    if (run.status !== "running") throw new Error("Run is not running");
    return run;
  };
  const readAttempt = (value: unknown) => {
    const row = z
      .object({ attempt_id: z.string(), record_json: z.string() })
      .parse(value);
    const record = ModelRecordSchema.parse(JSON.parse(row.record_json));
    parseInferenceAttempt(record.attempt);
    if (record.attempt.attemptId !== row.attempt_id)
      throw new Error("Model attempt identity is corrupt");
    return record;
  };
  const getAttempt = (runId: string, attemptId: string) => {
    const row = db
      .prepare(
        "SELECT attempt_id, record_json FROM model_attempts WHERE run_id = ? AND attempt_id = ?",
      )
      .get(runId, attemptId);
    if (!row) throw new Error("Model attempt has no committed dispatch");
    return readAttempt(row);
  };
  const updateAttempt = (runId: string, record: RecordedModelAttempt) => {
    db.prepare(
      "UPDATE model_attempts SET record_json = ? WHERE run_id = ? AND attempt_id = ?",
    ).run(
      JSON.stringify(ModelRecordSchema.parse(record)),
      runId,
      record.attempt.attemptId,
    );
  };

  return {
    async startModelAttempt(runId, executionAttemptId, candidate) {
      const attempt = parseInferenceAttempt(candidate);
      if (attempt.lifecycle !== "started")
        throw new Error("Dispatch requires a started inference attempt");
      transaction(() => {
        const run = owningRun(runId, executionAttemptId);
        input.assertDispatchAllowed?.(runId);
        const now = new Date().toISOString();
        const limits = run.spec.limits;
        if (limits?.deadlineAt && Date.now() >= Date.parse(limits.deadlineAt))
          throw new RunLimitError("Recorded run deadline expired");
        const count = db
          .prepare(
            "SELECT COUNT(*) AS count FROM model_attempts WHERE run_id = ?",
          )
          .get(runId) as { count: number };
        if (
          limits?.maxModelAttempts !== undefined &&
          count.count >= limits.maxModelAttempts
        ) {
          throw new RunLimitError(
            "Recorded run model request budget exhausted",
          );
        }
        const record: RecordedModelAttempt = {
          schemaVersion: 1,
          attempt,
          context: input.getContextReference(runId),
          toolCalls: [],
          startedAt: now,
          updatedAt: now,
        };
        db.prepare(
          "INSERT INTO model_attempts (run_id, attempt_id, record_json) VALUES (?, ?, ?)",
        ).run(
          runId,
          attempt.attemptId,
          JSON.stringify(ModelRecordSchema.parse(record)),
        );
      });
    },
    async observeModelToolCall(
      runId,
      executionAttemptId,
      attemptId,
      candidate,
    ) {
      const call = ToolCallSchema.parse(candidate);
      transaction(() => {
        owningRun(runId, executionAttemptId);
        const record = getAttempt(runId, attemptId);
        if (!["started", "partial"].includes(record.attempt.lifecycle))
          throw new Error("Model attempt is already settled");
        if (
          record.toolCalls.some(
            (previous) => previous.toolCallId === call.toolCallId,
          )
        ) {
          throw new Error("Model tool call was already observed");
        }
        updateAttempt(runId, {
          ...record,
          attempt: { ...record.attempt, lifecycle: "partial" },
          toolCalls: [...record.toolCalls, call],
          updatedAt: new Date().toISOString(),
        });
      });
    },
    async settleModelAttempt(runId, executionAttemptId, candidate) {
      const attempt = parseInferenceAttempt(candidate);
      if (attempt.lifecycle === "started")
        throw new Error(
          "Settlement requires a terminal or partial inference attempt",
        );
      transaction(() => {
        owningRun(runId, executionAttemptId);
        const record = getAttempt(runId, attempt.attemptId);
        for (const key of [
          "idempotencyKey",
          "lineage",
          "operationKind",
          "attribution",
          "requested",
        ] as const) {
          if (!isDeepStrictEqual(attempt[key], record.attempt[key]))
            throw new Error("Model attempt identity changed");
        }
        if (isDeepStrictEqual(attempt, record.attempt)) return;
        if (
          !["started", "partial"].includes(record.attempt.lifecycle) &&
          !(
            record.attempt.lifecycle === "failed" &&
            attempt.lifecycle === "retried"
          )
        ) {
          throw new Error("Model attempt is already settled");
        }
        updateAttempt(runId, {
          ...record,
          attempt,
          updatedAt: new Date().toISOString(),
        });
      });
    },
    async recordRetry(runId, executionAttemptId, candidate) {
      const decision = RetryDecisionSchema.parse(candidate);
      transaction(() => {
        owningRun(runId, executionAttemptId);
        const now = Date.now();
        const row = db
          .prepare(
            "SELECT COALESCE(MAX(sequence), 0) AS sequence FROM model_retries WHERE run_id = ?",
          )
          .get(runId) as { sequence: number };
        const record = RetryRecordSchema.parse({
          ...decision,
          sequence: row.sequence + 1,
          scheduledAt: new Date(now).toISOString(),
          dueAt: new Date(now + decision.delayMs).toISOString(),
        });
        db.prepare(
          "INSERT INTO model_retries (run_id, sequence, record_json) VALUES (?, ?, ?)",
        ).run(runId, record.sequence, JSON.stringify(record));
      });
    },
    async listModelAttempts(runId) {
      return db
        .prepare(
          "SELECT attempt_id, record_json FROM model_attempts WHERE run_id = ? ORDER BY rowid",
        )
        .all(runId)
        .map(readAttempt);
    },
    async listRetries(runId) {
      return db
        .prepare(
          "SELECT sequence, record_json FROM model_retries WHERE run_id = ? ORDER BY sequence",
        )
        .all(runId)
        .map((value) => {
          const row = z
            .object({
              sequence: z.number().int().positive(),
              record_json: z.string(),
            })
            .parse(value);
          const record = RetryRecordSchema.parse(JSON.parse(row.record_json));
          if (record.sequence !== row.sequence)
            throw new Error("Retry sequence is corrupt");
          return record;
        });
    },
  };
}
