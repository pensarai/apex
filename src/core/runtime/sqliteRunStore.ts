import { randomUUID } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { type ModelMessage, modelMessageSchema } from "ai";
import { z } from "zod";
import { newSessionId } from "../id/id";
import { getCurrentVersion } from "../installation";
import type { RunControlStore } from "./runControlStore";
import type { RunModelStore } from "./runModelStore";
import {
  type RecordedRunSpec,
  RecordedRunSpecSchema,
  type RunRecord,
  RunRecordSchema,
} from "./runStore";
import type { RunToolStore } from "./runToolStore";
import {
  CONTROL_STORE_SCHEMA_SQL,
  createSqliteControlStore,
} from "./sqliteControlStore";
import {
  createSqliteModelStore,
  MODEL_STORE_SCHEMA_SQL,
} from "./sqliteModelStore";
import {
  createSqliteToolStore,
  TOOL_STORE_SCHEMA_SQL,
} from "./sqliteToolStore";

type SqlValue = string | number | null;
interface Database {
  exec(sql: string): void;
  prepare(sql: string): {
    get(...values: SqlValue[]): unknown;
    all(...values: SqlValue[]): unknown[];
    run(...values: SqlValue[]): unknown;
  };
  close(): void;
}

const APPLICATION_ID = 0x41505258;
const STORE_VERSION = 5;

const EvidenceSchema = z
  .object({
    rootPath: z.string().refine(path.isAbsolute),
    files: z.array(
      z
        .object({
          path: z
            .string()
            .min(1)
            .refine(
              (value) =>
                !path.isAbsolute(value) && !value.split(/[\\/]/).includes(".."),
            ),
          sha256: z.string().regex(/^[a-f0-9]{64}$/),
          bytes: z.number().int().nonnegative(),
        })
        .strict(),
    ),
  })
  .strict();

const ContextChangeSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("replace"),
      messages: z.array(modelMessageSchema),
      system: z.string().nullable(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("append"),
      messages: z.array(modelMessageSchema),
    })
    .strict(),
]);

function readContextRow(value: unknown) {
  try {
    const row = z
      .object({
        epoch: z.number().int().positive(),
        revision: z.number().int().positive(),
        change_json: z.string(),
      })
      .parse(value);
    const change: unknown = JSON.parse(row.change_json);
    return {
      epoch: row.epoch,
      revision: row.revision,
      change: ContextChangeSchema.parse(change),
    };
  } catch (cause) {
    throw new Error("Run context is corrupt or has an unsupported schema", {
      cause,
    });
  }
}

function transaction<T>(db: Database, operation: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const value = operation();
    db.exec("COMMIT");
    return value;
  } catch (error) {
    try {
      db.exec("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError(
        [error, rollbackError],
        "Run transaction failed",
      );
    }
    throw error;
  }
}

function readRecord(
  value: unknown,
  expectedRunId?: string,
): RunRecord | undefined {
  if (value === undefined || value === null) return undefined;
  try {
    const row = value as { record_json: string };
    const record = RunRecordSchema.parse(JSON.parse(row.record_json));
    if (expectedRunId && record.spec.runId !== expectedRunId) {
      throw new Error("Run identity mismatch");
    }
    return record;
  } catch (cause) {
    throw new Error("Run record is corrupt or has an unsupported schema", {
      cause,
    });
  }
}

export async function openSqliteRunStore(
  filename = path.join(
    process.env.PENSAR_DATA_DIR ?? path.join(os.homedir(), ".pensar"),
    "runtime",
    "runs.sqlite",
  ),
): Promise<RunModelStore & RunToolStore & RunControlStore & { close(): void }> {
  // Leave the other runtime's builtin unresolved in both bundled distributions.
  const moduleName = typeof Bun !== "undefined" ? "bun:sqlite" : "node:sqlite";
  let sqlite: {
    Database?: new (filename: string) => Database;
    DatabaseSync?: new (filename: string) => Database;
  };
  try {
    sqlite = createRequire(import.meta.url)(moduleName);
  } catch (cause) {
    throw new Error("Recorded runs require Bun or Node 22.13+", { cause });
  }
  const Constructor = sqlite.Database ?? sqlite.DatabaseSync;
  if (!Constructor) throw new Error("SQLite runtime is unavailable");

  const resolved = path.resolve(filename);
  await mkdir(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const file = await open(resolved, "a", 0o600);
  await file.close();
  const db = new Constructor(resolved);
  try {
    db.exec("PRAGMA busy_timeout = 5000");
    db.exec("PRAGMA foreign_keys = ON");
    transaction(db, () => {
      const application = db.prepare("PRAGMA application_id").get() as {
        application_id: number;
      };
      const version = db.prepare("PRAGMA user_version").get() as {
        user_version: number;
      };
      if (
        application.application_id !== 0 &&
        application.application_id !== APPLICATION_ID
      ) {
        throw new Error("Database is not an Apex run store");
      }
      if (![0, 1, 2, 3, 4, STORE_VERSION].includes(version.user_version)) {
        throw new Error(
          `Unsupported run store version: ${version.user_version}`,
        );
      }
      if (application.application_id === 0) {
        const tables = db
          .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
          .all();
        if (tables.length || version.user_version !== 0) {
          throw new Error("Refusing to initialize an existing database");
        }
        db.exec(`
          CREATE TABLE runs (
            run_id TEXT PRIMARY KEY NOT NULL,
            record_json TEXT NOT NULL
          );
          PRAGMA application_id = ${APPLICATION_ID};
          PRAGMA user_version = 1;
        `);
      } else if (version.user_version === 0) {
        throw new Error("Run store schema version is missing");
      }
      if (version.user_version < 2) {
        db.exec(`
          CREATE TABLE run_context (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            revision INTEGER NOT NULL CHECK(revision > 0),
            epoch INTEGER NOT NULL CHECK(epoch > 0),
            change_json TEXT NOT NULL,
            PRIMARY KEY(run_id, revision)
          );
          CREATE TABLE run_evidence (
            run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(run_id),
            evidence_json TEXT NOT NULL
          );
          PRAGMA user_version = 2;
        `);
      }
      if (version.user_version < 3) {
        db.exec(MODEL_STORE_SCHEMA_SQL);
        db.exec("PRAGMA user_version = 3");
      }
      if (version.user_version < 4) {
        db.exec(TOOL_STORE_SCHEMA_SQL);
        db.exec("PRAGMA user_version = 4");
      }
      if (version.user_version < 5) {
        db.exec(CONTROL_STORE_SCHEMA_SQL);
        db.exec(`PRAGMA user_version = ${STORE_VERSION}`);
      }
    });
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA synchronous = FULL");

    const get = (runId: string) =>
      readRecord(
        db.prepare("SELECT record_json FROM runs WHERE run_id = ?").get(runId),
        runId,
      );

    const headContext = (runId: string) => {
      const row = db
        .prepare(
          "SELECT epoch, revision, change_json FROM run_context WHERE run_id = ? ORDER BY revision DESC LIMIT 1",
        )
        .get(runId);
      return row ? readContextRow(row) : undefined;
    };

    const getEvidence = (runId: string) => {
      const row = db
        .prepare("SELECT evidence_json FROM run_evidence WHERE run_id = ?")
        .get(runId) as { evidence_json: string } | undefined;
      try {
        return row
          ? EvidenceSchema.parse(JSON.parse(row.evidence_json))
          : undefined;
      } catch (cause) {
        throw new Error(
          "Run evidence is corrupt or has an unsupported schema",
          { cause },
        );
      }
    };

    const commitEvidence = (
      runId: string,
      evidence: z.infer<typeof EvidenceSchema>,
    ) => {
      const nextEvidence = EvidenceSchema.parse(evidence);
      const previousEvidence = getEvidence(runId);
      if (
        previousEvidence &&
        previousEvidence.rootPath !== nextEvidence.rootPath
      ) {
        throw new Error("Session evidence location changed");
      }
      const files = new Map(
        previousEvidence?.files.map((ref) => [ref.path, ref]),
      );
      for (const ref of nextEvidence.files) files.set(ref.path, ref);
      const snapshot = {
        rootPath: nextEvidence.rootPath,
        files: [...files.values()].sort((a, b) => a.path.localeCompare(b.path)),
      };
      db.prepare(
        "INSERT INTO run_evidence (run_id, evidence_json) VALUES (?, ?) ON CONFLICT(run_id) DO UPDATE SET evidence_json = excluded.evidence_json",
      ).run(runId, JSON.stringify(snapshot));
    };

    const controlStore = createSqliteControlStore({
      db,
      transaction: (operation) => transaction(db, operation),
      getRun: get,
      getContextReference: (runId) => {
        const head = headContext(runId);
        return head ? { epoch: head.epoch, revision: head.revision } : null;
      },
    });

    return {
      ...controlStore.methods,
      ...createSqliteToolStore({
        db,
        assertToolApproved: controlStore.assertToolApproved,
        transaction: (operation) => transaction(db, operation),
        getRun: get,
        getContextReference: (runId) => {
          const head = headContext(runId);
          return head ? { epoch: head.epoch, revision: head.revision } : null;
        },
        commitEvidence,
      }),
      ...createSqliteModelStore({
        db,
        assertDispatchAllowed: controlStore.assertDispatchAllowed,
        transaction: (operation) => transaction(db, operation),
        getRun: get,
        getContextReference: (runId) => {
          const head = headContext(runId);
          return head ? { epoch: head.epoch, revision: head.revision } : null;
        },
      }),
      async commitContext(
        runId,
        attemptId,
        expectedRevision,
        change,
        evidence,
      ) {
        // Validate the JSON representation, not an in-memory value that JSON would lose.
        const serialized = JSON.stringify(change);
        const parsed = ContextChangeSchema.parse(JSON.parse(serialized));
        const nextEvidence = evidence && EvidenceSchema.parse(evidence);
        if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
          throw new Error("Invalid expected context revision");
        }
        return transaction(db, () => {
          const record = get(runId);
          if (!record || record.attemptId !== attemptId) {
            throw new Error("Execution attempt does not own this run");
          }
          if (record.status !== "running")
            throw new Error("Run is not running");
          const previous = headContext(runId);
          if ((previous?.revision ?? 0) !== expectedRevision) {
            throw new Error("Context revision conflict");
          }
          if (!previous && parsed.kind !== "replace") {
            throw new Error("Context requires an initial replacement");
          }
          const reference = {
            epoch: (previous?.epoch ?? 0) + (parsed.kind === "replace" ? 1 : 0),
            revision: expectedRevision + 1,
          };
          db.prepare(
            "INSERT INTO run_context (run_id, revision, epoch, change_json) VALUES (?, ?, ?, ?)",
          ).run(runId, reference.revision, reference.epoch, serialized);
          if (nextEvidence) {
            commitEvidence(runId, nextEvidence);
          }
          return reference;
        });
      },
      async getEvidence(runId) {
        return getEvidence(runId);
      },
      async getContext(runId) {
        // One query keeps the selected epoch and its deltas in one read snapshot.
        const rows = db
          .prepare(
            `SELECT epoch, revision, change_json FROM run_context
           WHERE run_id = ? AND epoch = (
             SELECT epoch FROM run_context WHERE run_id = ? ORDER BY revision DESC LIMIT 1
           ) ORDER BY revision`,
          )
          .all(runId, runId)
          .map(readContextRow);
        const base = rows[0];
        if (!base) return undefined;
        if (base.change.kind !== "replace") {
          throw new Error("Context base is missing or corrupt");
        }
        const messages: ModelMessage[] = [...base.change.messages];
        let revision = base.revision;
        for (const row of rows.slice(1)) {
          if (row.revision !== revision + 1 || row.change.kind !== "append") {
            throw new Error("Context sequence is corrupt");
          }
          messages.push(...row.change.messages);
          revision = row.revision;
        }
        return {
          epoch: base.epoch,
          revision,
          messages,
          system: base.change.system,
        };
      },
      async admit(input: RecordedRunSpec) {
        const spec = RecordedRunSpecSchema.parse(input);
        // Zod's fixed object shape supplies stable key order for admission equality.
        const serialized = JSON.stringify(spec);
        return transaction(db, () => {
          const existing = get(spec.runId);
          if (existing) {
            if (JSON.stringify(existing.spec) !== serialized) {
              throw new Error("Run ID already admitted with different inputs");
            }
            return { created: false, record: existing };
          }
          const now = new Date().toISOString();
          const record = RunRecordSchema.parse({
            schemaVersion: 1,
            spec,
            sessionId: newSessionId(),
            attemptId: `exec_${randomUUID()}`,
            runtimeVersion: getCurrentVersion(),
            status: "admitted",
            admittedAt: now,
            updatedAt: now,
          });
          db.prepare(
            "INSERT INTO runs (run_id, record_json) VALUES (?, ?)",
          ).run(spec.runId, JSON.stringify(record));
          return { created: true, record };
        });
      },
      async get(runId) {
        return get(runId);
      },
      async list() {
        return db
          .prepare("SELECT run_id, record_json FROM runs ORDER BY run_id")
          .all()
          .map((row) => {
            const record = readRecord(row, (row as { run_id: string }).run_id);
            if (!record) throw new Error("Run record is missing");
            return record;
          });
      },
      async transition(runId, attemptId, status) {
        if (
          !["running", "paused", "completed", "failed", "cancelled"].includes(
            status,
          )
        ) {
          throw new Error("Invalid run transition status");
        }
        return transaction(db, () => {
          const previous = get(runId);
          if (!previous) throw new Error("Run does not exist");
          if (previous.attemptId !== attemptId) {
            throw new Error("Execution attempt does not own this run");
          }
          const intent = controlStore.readControl(runId)?.intent;
          if (intent === "stop" && status !== "failed") status = "cancelled";
          if (status === "paused" && intent !== "pause") {
            throw new Error("Pausing requires a persisted pause request");
          }
          if (previous.status === status) return previous;
          if (
            !["admitted", "running"].includes(previous.status) ||
            (previous.status === "admitted" && status === "completed")
          ) {
            throw new Error(
              `Invalid run transition: ${previous.status} -> ${status}`,
            );
          }
          const record = RunRecordSchema.parse({
            ...previous,
            status,
            updatedAt: new Date().toISOString(),
          });
          db.prepare("UPDATE runs SET record_json = ? WHERE run_id = ?").run(
            JSON.stringify(record),
            runId,
          );
          return record;
        });
      },
      close: () => db.close(),
    };
  } catch (error) {
    db.close();
    throw error;
  }
}
