import { randomUUID } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { newSessionId } from "../id/id";
import { getCurrentVersion } from "../installation";
import {
  type RecordedRunSpec,
  RecordedRunSpecSchema,
  type RunRecord,
  RunRecordSchema,
  type RunStore,
} from "./runStore";

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
const STORE_VERSION = 1;

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
): Promise<RunStore & { close(): void }> {
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
      if (
        version.user_version !== 0 &&
        version.user_version !== STORE_VERSION
      ) {
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
          PRAGMA user_version = ${STORE_VERSION};
        `);
      } else if (version.user_version !== STORE_VERSION) {
        throw new Error("Run store schema version is missing");
      }
    });
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA synchronous = FULL");

    const get = (runId: string) =>
      readRecord(
        db.prepare("SELECT record_json FROM runs WHERE run_id = ?").get(runId),
        runId,
      );

    return {
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
        if (!["running", "completed", "failed", "cancelled"].includes(status)) {
          throw new Error("Invalid run transition status");
        }
        return transaction(db, () => {
          const previous = get(runId);
          if (!previous) throw new Error("Run does not exist");
          if (previous.attemptId !== attemptId) {
            throw new Error("Execution attempt does not own this run");
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
