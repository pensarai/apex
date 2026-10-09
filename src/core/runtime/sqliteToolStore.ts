import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { type ToolResultPart, toolModelMessageSchema } from "ai";
import { z } from "zod";
import type { ContextReference } from "./runContext";
import type { EvidenceReference } from "./runEvidence";
import type { RunRecord } from "./runStore";
import type {
  RecordedToolInput,
  RecordedToolOperation,
  RecordedToolPolicy,
  RunToolStore,
} from "./runToolStore";

export const TOOL_STORE_SCHEMA_SQL = `
  CREATE TABLE tool_journals (
    run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(run_id),
    version INTEGER NOT NULL,
    execution_attempt_id TEXT NOT NULL
  );
  CREATE TABLE tool_operations (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    tool_call_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(run_id, tool_call_id),
    UNIQUE(run_id, sequence)
  );
`;

const OPERATION_ID_PATTERN =
  /^top_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EXECUTION_ATTEMPT_PATTERN =
  /^exec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const JOURNAL_VERSION = 1;

const evidenceReferenceSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .refine(
        (value) => !isAbsolute(value) && !value.split(/[\\/]/).includes(".."),
      ),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    bytes: z.number().int().nonnegative(),
  })
  .strict();

const evidenceSchema = z
  .object({
    rootPath: z.string().refine(isAbsolute),
    files: z.array(evidenceReferenceSchema),
  })
  .strict();

// The SDK keeps its tool-result output schema internal; the tool-result
// branch of the exported toolModelMessageSchema validates the same shape.
const outputSchema = z.custom<ToolResultPart["output"]>(
  (value) =>
    toolModelMessageSchema.safeParse({
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "validation",
          toolName: "validation",
          output: value,
        },
      ],
    }).success,
);

// Settled records must carry their output and evidence; unsettled records
// must carry neither. Validated on every read, not only at write time.
const operationCommonShape = {
  schemaVersion: z.literal(1),
  operationId: z.string().regex(OPERATION_ID_PATTERN),
  executionAttemptId: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
  toolCallId: z.string().min(1),
  toolName: z.string().min(1),
  input: z.custom<unknown>((value) => value !== undefined),
  policy: z.enum([
    "read_only",
    "external_effect",
    "local_mutation",
    "shell_state",
  ]),
  sequence: z.number().int().positive(),
  context: z
    .object({
      epoch: z.number().int().positive(),
      revision: z.number().int().positive(),
    })
    .strict(),
  startedAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
};

const ToolOperationRecordSchema = z.discriminatedUnion("state", [
  z.object({ ...operationCommonShape, state: z.literal("started") }).strict(),
  z
    .object({
      ...operationCommonShape,
      state: z.literal("settled"),
      output: outputSchema,
      evidence: evidenceSchema,
    })
    .strict(),
  z
    .object({ ...operationCommonShape, state: z.literal("outcome_unknown") })
    .strict(),
]);

const JournalRowSchema = z
  .object({
    version: z.literal(JOURNAL_VERSION),
    execution_attempt_id: z.string().regex(EXECUTION_ATTEMPT_PATTERN),
  })
  .strict();

interface ToolDatabase {
  prepare(sql: string): {
    get(...values: (string | number)[]): unknown;
    all(...values: (string | number)[]): unknown[];
    run(...values: (string | number)[]): unknown;
  };
}

type ToolMethods = Pick<
  RunToolStore,
  | "initializeToolJournal"
  | "hasToolJournal"
  | "startToolOperation"
  | "settleToolOperation"
  | "markToolOutcomeUnknown"
  | "listToolOperations"
>;

/** The persisted form is the only input ever stored — a value JSON cannot round-trip exactly is rejected, not silently narrowed. */
function durableInput(input: unknown, kind = "input"): unknown {
  const serialized = JSON.stringify(input);
  const roundTrip = JSON.parse(serialized);
  if (!isDeepStrictEqual(roundTrip, input)) {
    throw new Error(
      `Tool operation ${kind} is not completely JSON-serializable`,
    );
  }
  return roundTrip;
}

function toolInput(candidate: RecordedToolInput): {
  toolCallId: string;
  toolName: string;
  policy: RecordedToolPolicy;
  input: unknown;
} {
  return {
    toolCallId: z.string().min(1).parse(candidate.toolCallId),
    toolName: z.string().min(1).parse(candidate.toolName),
    policy: z
      .enum(["read_only", "external_effect", "local_mutation", "shell_state"])
      .parse(candidate.policy),
    input: durableInput(candidate.input),
  };
}

export function createSqliteToolStore(input: {
  db: ToolDatabase;
  transaction<T>(operation: () => T): T;
  getRun(runId: string): RunRecord | undefined;
  getContextReference(runId: string): ContextReference | null;
  /**
   * Merges refs into the run's current evidence snapshot on the same DB.
   * Synchronous by contract: it runs inside the caller's transaction and
   * must not open a nested one; a throw rolls the settlement back with it.
   */
  commitEvidence(
    runId: string,
    evidence: { rootPath: string; files: EvidenceReference[] },
  ): void;
}): ToolMethods {
  const { db, transaction } = input;

  // A corrupt or future-version journal row surfaces explicitly instead of
  // reading as absent or valid.
  const readJournal = (runId: string) => {
    const row = db
      .prepare(
        "SELECT version, execution_attempt_id FROM tool_journals WHERE run_id = ?",
      )
      .get(runId);
    if (row == null) return undefined;
    try {
      return JournalRowSchema.parse(row);
    } catch (cause) {
      throw new Error("Tool journal is corrupt or has an unsupported version", {
        cause,
      });
    }
  };

  // Writes require the journal's enrolled attempt to match the caller's.
  const enrolledRun = (runId: string, executionAttemptId: string) => {
    const run = input.getRun(runId);
    if (!run || run.attemptId !== executionAttemptId) {
      throw new Error("Execution attempt does not own this run");
    }
    if (run.status !== "running") throw new Error("Run is not running");
    const journal = readJournal(runId);
    if (!journal)
      throw new Error("Tool journal is not initialized for this run");
    if (journal.execution_attempt_id !== executionAttemptId) {
      throw new Error("Tool journal is enrolled by another execution attempt");
    }
    return run;
  };

  const readOperation = (value: unknown): RecordedToolOperation => {
    const row = z
      .object({
        tool_call_id: z.string(),
        sequence: z.number().int().positive(),
        record_json: z.string(),
      })
      .parse(value);
    const record = ToolOperationRecordSchema.parse(JSON.parse(row.record_json));
    if (
      record.toolCallId !== row.tool_call_id ||
      record.sequence !== row.sequence
    ) {
      throw new Error("Tool operation identity is corrupt");
    }
    return record;
  };

  const getOperation = (runId: string, toolCallId: string) => {
    const row = db
      .prepare(
        "SELECT tool_call_id, sequence, record_json FROM tool_operations WHERE run_id = ? AND tool_call_id = ?",
      )
      .get(runId, toolCallId);
    if (!row) throw new Error("Tool operation has no committed start");
    return readOperation(row);
  };

  const updateOperation = (runId: string, record: RecordedToolOperation) => {
    db.prepare(
      "UPDATE tool_operations SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
    ).run(
      JSON.stringify(ToolOperationRecordSchema.parse(record)),
      runId,
      record.toolCallId,
    );
  };

  return {
    async initializeToolJournal(runId, executionAttemptId) {
      transaction(() => {
        const run = input.getRun(runId);
        if (!run || run.attemptId !== executionAttemptId) {
          throw new Error("Execution attempt does not own this run");
        }
        if (run.status !== "running") throw new Error("Run is not running");
        const journal = readJournal(runId);
        if (journal) {
          if (journal.execution_attempt_id !== executionAttemptId) {
            throw new Error(
              "Tool journal is enrolled by another execution attempt",
            );
          }
          return;
        }
        db.prepare(
          "INSERT INTO tool_journals (run_id, version, execution_attempt_id) VALUES (?, ?, ?)",
        ).run(runId, JOURNAL_VERSION, executionAttemptId);
      });
    },
    async hasToolJournal(runId) {
      return readJournal(runId) !== undefined;
    },
    async startToolOperation(runId, executionAttemptId, candidate) {
      const {
        toolCallId,
        toolName,
        policy,
        input: durable,
      } = toolInput(candidate);
      return transaction(() => {
        enrolledRun(runId, executionAttemptId);
        const context = input.getContextReference(runId);
        if (!context) {
          throw new Error("Tool operation requires a committed context");
        }
        const existing = db
          .prepare(
            "SELECT tool_call_id, sequence, record_json FROM tool_operations WHERE run_id = ? AND tool_call_id = ?",
          )
          .get(runId, toolCallId);
        if (existing) {
          const record = readOperation(existing);
          if (
            record.toolName !== toolName ||
            record.policy !== policy ||
            !isDeepStrictEqual(record.input, durable)
          ) {
            throw new Error(
              "Tool operation was already started with different inputs",
            );
          }
          return { created: false, operation: record };
        }
        const sequence =
          (
            db
              .prepare(
                "SELECT COALESCE(MAX(sequence), 0) AS sequence FROM tool_operations WHERE run_id = ?",
              )
              .get(runId) as { sequence: number }
          ).sequence + 1;
        const now = new Date().toISOString();
        const record: RecordedToolOperation = {
          schemaVersion: 1,
          operationId: `top_${randomUUID()}`,
          executionAttemptId,
          toolCallId,
          toolName,
          input: durable,
          policy,
          sequence,
          context,
          state: "started",
          startedAt: now,
          updatedAt: now,
        };
        db.prepare(
          "INSERT INTO tool_operations (run_id, tool_call_id, sequence, record_json) VALUES (?, ?, ?, ?)",
        ).run(
          runId,
          toolCallId,
          sequence,
          JSON.stringify(ToolOperationRecordSchema.parse(record)),
        );
        return { created: true, operation: record };
      });
    },
    async settleToolOperation(
      runId,
      executionAttemptId,
      toolCallId,
      output,
      evidence,
    ) {
      const settledOutput = outputSchema.parse(durableInput(output, "output"));
      const settledEvidence = evidenceSchema.parse(evidence);
      transaction(() => {
        enrolledRun(runId, executionAttemptId);
        const record = getOperation(runId, toolCallId);
        if (record.state === "settled") {
          if (
            !isDeepStrictEqual(record.output, settledOutput) ||
            !isDeepStrictEqual(record.evidence, settledEvidence)
          ) {
            throw new Error(
              "Tool operation was already settled with a different outcome",
            );
          }
          return;
        }
        if (record.state !== "started") {
          throw new Error(
            "Tool operation outcome is already recorded as unknown",
          );
        }
        updateOperation(runId, {
          ...record,
          state: "settled",
          output: settledOutput,
          evidence: settledEvidence,
          updatedAt: new Date().toISOString(),
        });
        // Same transaction as the settlement: a crash before the next
        // context checkpoint still leaves the latest artifact refs committed.
        input.commitEvidence(runId, settledEvidence);
      });
    },
    async markToolOutcomeUnknown(runId, executionAttemptId, toolCallId) {
      transaction(() => {
        enrolledRun(runId, executionAttemptId);
        const record = getOperation(runId, toolCallId);
        if (record.state === "outcome_unknown") return;
        if (record.state !== "started") {
          throw new Error("Tool operation was already settled");
        }
        updateOperation(runId, {
          ...record,
          state: "outcome_unknown",
          updatedAt: new Date().toISOString(),
        });
      });
    },
    async listToolOperations(runId) {
      return db
        .prepare(
          "SELECT tool_call_id, sequence, record_json FROM tool_operations WHERE run_id = ? ORDER BY sequence",
        )
        .all(runId)
        .map(readOperation);
    },
  };
}
