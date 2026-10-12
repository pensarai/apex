import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startInferenceAttempt } from "../ai/inference-attempt";
import { RunLimitError, type RunModelStore } from "./runModelStore";
import type { RecordedRunSpec } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

// Model-attempt persistence tests through the real SQLite store.

type Store = RunModelStore & { close(): void };

let tempDirs: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("modelstore-db-"), "runs.sqlite");
}

const cwdByRunId = new Map<string, string>();

function spec(
  runId: string,
  limits?: RecordedRunSpec["limits"],
): RecordedRunSpec {
  let cwd = cwdByRunId.get(runId);
  if (!cwd) {
    cwd = tempDir("modelstore-cwd-");
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
    ...(limits ? { limits } : {}),
  };
}

// The factory mints schema-valid envelopes; handles expose settlements.
function newAttempt() {
  return startInferenceAttempt({
    operationKind: "agent.stream",
    requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
  });
}

// Fault injection needs a raw connection — the only place tests reach past
// the public API. createRequire, not dynamic import: vite-node cannot
// resolve the runtime-selected sqlite builtin.
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

async function withStore<T>(
  dbPath: string,
  fn: (store: Store) => Promise<T>,
): Promise<T> {
  const store = await openSqliteRunStore(dbPath);
  try {
    return await fn(store);
  } finally {
    store.close();
  }
}

async function admitRunning(
  store: Store,
  runId: string,
  limits?: RecordedRunSpec["limits"],
): Promise<string> {
  const admitted = await store.admit(spec(runId, limits));
  await store.transition(runId, admitted.record.attemptId, "running");
  return admitted.record.attemptId;
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("model attempt dispatch and persistence", () => {
  it("persists a started attempt with unknown usage and no context; reopen keeps it", async () => {
    const dbPath = tempDb();
    const runId = "run_model_persist";
    const handle = newAttempt();
    await withStore(dbPath, async (store) => {
      const exec = await admitRunning(store, runId);
      await store.startModelAttempt(runId, exec, handle.started);

      const attempts = await store.listModelAttempts(runId);
      expect(attempts).toHaveLength(1);
      expect(attempts[0]?.attempt.attemptId).toBe(handle.attemptId);
      expect(attempts[0]?.attempt.lifecycle).toBe("started");
      // Unknown usage is explicit nulls, never coerced to zero.
      expect(attempts[0]?.attempt.tokens).toEqual({
        inclusiveInput: null,
        uncachedInput: null,
        cacheRead: null,
        cacheWrite: null,
        output: null,
      });
      // No context committed yet → the dispatch records no context reference.
      expect(attempts[0]?.context).toBeNull();
      expect(attempts[0]?.toolCalls).toEqual([]);
    });

    await withStore(dbPath, async (store) => {
      const attempts = await store.listModelAttempts(runId);
      expect(attempts).toHaveLength(1);
      expect(attempts[0]?.attempt.attemptId).toBe(handle.attemptId);
      expect(attempts[0]?.attempt.lifecycle).toBe("started");
    });
  });

  it("rejects a duplicate dispatch of the same attempt id", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_dup";
      const exec = await admitRunning(store, runId);
      const handle = newAttempt();
      await store.startModelAttempt(runId, exec, handle.started);

      await expect(
        store.startModelAttempt(runId, exec, handle.started),
      ).rejects.toThrow();
      expect(await store.listModelAttempts(runId)).toHaveLength(1);
    });
  });

  it("requires the owning attempt and a running run", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_owner";
      const admitted = await store.admit(spec(runId));

      // Admitted (not yet running).
      await expect(
        store.startModelAttempt(
          runId,
          admitted.record.attemptId,
          newAttempt().started,
        ),
      ).rejects.toThrow(/Run is not running/);

      await store.transition(runId, admitted.record.attemptId, "running");

      // Wrong execution attempt.
      await expect(
        store.startModelAttempt(
          runId,
          "exec_00000000-0000-4000-8000-000000000000",
          newAttempt().started,
        ),
      ).rejects.toThrow(/does not own this run/);

      // Terminal status.
      await store.transition(runId, admitted.record.attemptId, "completed");
      await expect(
        store.startModelAttempt(
          runId,
          admitted.record.attemptId,
          newAttempt().started,
        ),
      ).rejects.toThrow(/Run is not running/);
    });
  });

  it("records the committed context reference at dispatch time", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_ctx";
      const exec = await admitRunning(store, runId);

      await store.commitContext(runId, exec, 0, {
        kind: "replace",
        messages: [{ role: "user", content: "first" }],
        system: null,
      });
      const first = newAttempt();
      await store.startModelAttempt(runId, exec, first.started);
      expect((await store.listModelAttempts(runId))[0]?.context).toEqual({
        epoch: 1,
        revision: 1,
      });

      await store.commitContext(runId, exec, 1, {
        kind: "append",
        messages: [{ role: "assistant", content: "second" }],
      });
      const second = newAttempt();
      await store.startModelAttempt(runId, exec, second.started);

      const attempts = await store.listModelAttempts(runId);
      // Dispatch order preserved; the later dispatch sees revision 2.
      expect(attempts[0]?.context).toEqual({ epoch: 1, revision: 1 });
      expect(attempts[1]?.context).toEqual({ epoch: 1, revision: 2 });
    });
  });
});

describe("settlement and tool observation", () => {
  it("settles completed with unknown usage, and failed -> retried stays valid", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_settle";
      const exec = await admitRunning(store, runId);
      const handle = newAttempt();
      await store.startModelAttempt(runId, exec, handle.started);

      // Complete without usage → unknown tokens persist as nulls.
      const completed = handle.complete();
      await store.settleModelAttempt(runId, exec, completed);
      let attempts = await store.listModelAttempts(runId);
      expect(attempts[0]?.attempt.lifecycle).toBe("completed");
      expect(attempts[0]?.attempt.tokens.output).toBeNull();

      // A byte-identical re-settlement is an idempotent no-op — settle is a
      // sync fire-and-forget enqueue, so terminal callbacks can double-fire.
      await store.settleModelAttempt(runId, exec, handle.complete());
      attempts = await store.listModelAttempts(runId);
      expect(attempts[0]?.attempt.lifecycle).toBe("completed");

      // A different envelope for the settled attempt is rejected.
      await expect(
        store.settleModelAttempt(runId, exec, handle.fail()),
      ).rejects.toThrow(/already settled/);
    });

    await withStore(tempDb(), async (store) => {
      const runId = "run_model_retried";
      const exec = await admitRunning(store, runId);
      const handle = newAttempt();
      await store.startModelAttempt(runId, exec, handle.started);

      await store.settleModelAttempt(runId, exec, handle.fail());
      // failed -> retried is the one allowed post-terminal transition.
      await store.settleModelAttempt(runId, exec, handle.retried());

      const attempts = await store.listModelAttempts(runId);
      expect(attempts[0]?.attempt.lifecycle).toBe("retried");

      // retried is terminal for the store; completing the same id rejects.
      await expect(
        store.settleModelAttempt(runId, exec, handle.complete()),
      ).rejects.toThrow(/already settled/);
    });
  });

  it("rejects settlement of an attempt that was never dispatched", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_nodispatch";
      const exec = await admitRunning(store, runId);
      await expect(
        store.settleModelAttempt(runId, exec, newAttempt().complete()),
      ).rejects.toThrow(/no committed dispatch/);
    });
  });

  it("persists observed tool calls before exposure and rejects duplicates", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_tools";
      const exec = await admitRunning(store, runId);
      const handle = newAttempt();
      await store.startModelAttempt(runId, exec, handle.started);

      const call = { toolCallId: "tc_1", toolName: "http_request" };
      await store.observeModelToolCall(runId, exec, handle.attemptId, call);

      let attempts = await store.listModelAttempts(runId);
      expect(attempts[0]?.toolCalls).toEqual([call]);
      // Observation marks the attempt partial — tools were exposed.
      expect(attempts[0]?.attempt.lifecycle).toBe("partial");

      await expect(
        store.observeModelToolCall(runId, exec, handle.attemptId, call),
      ).rejects.toThrow(/already observed/);

      // A distinct call id appends.
      await store.observeModelToolCall(runId, exec, handle.attemptId, {
        toolCallId: "tc_2",
        toolName: "execute_command",
      });
      attempts = await store.listModelAttempts(runId);
      expect(attempts[0]?.toolCalls).toHaveLength(2);

      // After settlement, no further observations land.
      await store.settleModelAttempt(runId, exec, handle.complete());
      await expect(
        store.observeModelToolCall(runId, exec, handle.attemptId, {
          toolCallId: "tc_3",
          toolName: "http_request",
        }),
      ).rejects.toThrow(/already settled/);
    });
  });
});

describe("retry records", () => {
  it("persists sequence, timestamps, and counters; rejects count above max", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_retry";
      const exec = await admitRunning(store, runId);

      await store.recordRetry(runId, exec, {
        authority: "stream-rate-limit",
        count: 1,
        maxRetries: 20,
        delayMs: 1500,
      });
      await store.recordRetry(runId, exec, {
        authority: "stream-idle",
        count: 2,
        maxRetries: 20,
        delayMs: 0,
      });

      const retries = await store.listRetries(runId);
      expect(retries.map((r) => r.sequence)).toEqual([1, 2]);
      expect(retries[0]?.authority).toBe("stream-rate-limit");
      expect(retries[0]?.count).toBe(1);
      // dueAt is the scheduled backoff boundary: scheduledAt + delayMs.
      expect(
        Date.parse(retries[0]!.dueAt) - Date.parse(retries[0]!.scheduledAt),
      ).toBe(1500);
      expect(
        Date.parse(retries[1]!.dueAt) - Date.parse(retries[1]!.scheduledAt),
      ).toBe(0);

      // A counter past the authority's max is invalid, never recorded.
      await expect(
        store.recordRetry(runId, exec, {
          authority: "stream-rate-limit",
          count: 21,
          maxRetries: 20,
          delayMs: 100,
        }),
      ).rejects.toThrow();
      expect(await store.listRetries(runId)).toHaveLength(2);
    });
  });
});

describe("run limits gate dispatch", () => {
  it("exhausts the maxModelAttempts budget with RunLimitError", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_budget";
      const exec = await admitRunning(store, runId, {
        maxModelAttempts: 2,
      });

      await store.startModelAttempt(runId, exec, newAttempt().started);
      await store.startModelAttempt(runId, exec, newAttempt().started);

      await expect(
        store.startModelAttempt(runId, exec, newAttempt().started),
      ).rejects.toThrow(RunLimitError);
      // The two committed attempts remain inspectable.
      expect(await store.listModelAttempts(runId)).toHaveLength(2);
    });
  });

  it("rejects dispatch after the deadline with RunLimitError", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_model_deadline";
      const exec = await admitRunning(store, runId, {
        deadlineAt: new Date(Date.now() - 1000).toISOString(),
      });

      await expect(
        store.startModelAttempt(runId, exec, newAttempt().started),
      ).rejects.toThrow(RunLimitError);
      expect(await store.listModelAttempts(runId)).toHaveLength(0);
    });
  });
});

describe("write failures roll back", () => {
  it("a trigger-injected model_attempts insert failure leaves no row", async () => {
    const dbPath = tempDb();
    const runId = "run_model_trigger";
    let exec: string;
    await withStore(dbPath, async (store) => {
      exec = await admitRunning(store, runId);
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_model_insert BEFORE INSERT ON model_attempts " +
        "BEGIN SELECT RAISE(ABORT, 'injected model attempt failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(
        store.startModelAttempt(runId, exec!, newAttempt().started),
      ).rejects.toThrow();
      expect(await store.listModelAttempts(runId)).toHaveLength(0);
    });
  });
});

describe("v2 databases migrate to v3 preserving run, context, and evidence", () => {
  it("migrates a genuine B2 database and continues model recording", async () => {
    // Seed through the real store (records a genuine admitted run, a
    // committed context ladder, and an evidence snapshot), then rebuild the
    // file as exact B2 shape: runs + run_context + run_evidence only.
    const seedDb = tempDb();
    const runId = "run_model_migrate";
    const rootPath = tempDir("modelstore-evroot-");
    let exec: string;
    let recordJson: string;
    let contextRows: Array<[number, number, string]>;
    let evidenceJson: string;
    await withStore(seedDb, async (store) => {
      exec = await admitRunning(store, runId);
      await store.commitContext(
        runId,
        exec,
        0,
        {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: "system prompt",
        },
        {
          rootPath,
          files: [{ path: "a.txt", sha256: "0".repeat(64), bytes: 1 }],
        },
      );
      await store.commitContext(runId, exec, 1, {
        kind: "append",
        messages: [{ role: "assistant", content: "second" }],
      });
      recordJson = JSON.stringify((await store.get(runId))!);
    });
    const rawSeed = rawDb(seedDb);
    recordJson = (
      rawSeed
        .prepare("SELECT record_json FROM runs WHERE run_id = ?")
        .get(runId) as { record_json: string }
    ).record_json;
    contextRows = (
      rawSeed
        .prepare(
          "SELECT revision, epoch, change_json FROM run_context WHERE run_id = ? ORDER BY revision",
        )
        .all(runId) as Array<{
        revision: number;
        epoch: number;
        change_json: string;
      }>
    ).map(
      (r) => [r.revision, r.epoch, r.change_json] as [number, number, string],
    );
    evidenceJson = (
      rawSeed
        .prepare("SELECT evidence_json FROM run_evidence WHERE run_id = ?")
        .get(runId) as { evidence_json: string }
    ).evidence_json;
    rawSeed.close();

    const dbPath = tempDb();
    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TABLE runs (run_id TEXT PRIMARY KEY NOT NULL, record_json TEXT NOT NULL)",
    );
    raw
      .prepare("INSERT INTO runs (run_id, record_json) VALUES (?, ?)")
      .run(runId, recordJson!);
    raw.exec(`
      CREATE TABLE run_context (
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        revision INTEGER NOT NULL CHECK(revision > 0),
        epoch INTEGER NOT NULL CHECK(epoch > 0),
        change_json TEXT NOT NULL,
        PRIMARY KEY(run_id, revision)
      );
    `);
    for (const [revision, epoch, changeJson] of contextRows!) {
      raw
        .prepare(
          "INSERT INTO run_context (run_id, revision, epoch, change_json) VALUES (?, ?, ?, ?)",
        )
        .run(runId, revision, epoch, changeJson);
    }
    raw.exec(`
      CREATE TABLE run_evidence (
        run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(run_id),
        evidence_json TEXT NOT NULL
      );
    `);
    raw
      .prepare("INSERT INTO run_evidence (run_id, evidence_json) VALUES (?, ?)")
      .run(runId, evidenceJson!);
    raw.exec("PRAGMA application_id = 0x41505258");
    raw.exec("PRAGMA user_version = 2");
    raw.close();

    await withStore(dbPath, async (store) => {
      // Pre-existing run, context, and evidence survive the migration.
      const record = await store.get(runId);
      expect(record?.attemptId).toBe(exec!);
      const context = await store.getContext(runId);
      expect(context?.epoch).toBe(1);
      expect(context?.revision).toBe(2);
      expect(context?.messages).toEqual([
        { role: "user", content: "first" },
        { role: "assistant", content: "second" },
      ]);
      expect((await store.getEvidence(runId))?.files).toEqual([
        { path: "a.txt", sha256: "0".repeat(64), bytes: 1 },
      ]);

      // v2 had no model recording; migration starts it empty but functional.
      expect(await store.listModelAttempts(runId)).toEqual([]);
      expect(await store.listRetries(runId)).toEqual([]);

      const handle = newAttempt();
      await store.startModelAttempt(runId, exec!, handle.started);
      await store.recordRetry(runId, exec!, {
        authority: "stream-rate-limit",
        count: 1,
        maxRetries: 20,
        delayMs: 500,
      });
      expect(await store.listModelAttempts(runId)).toHaveLength(1);
      expect((await store.listRetries(runId))[0]?.sequence).toBe(1);
    });
  });
});

describe("budget and retry inspection survive reopen", () => {
  it("reopened store enforces the remaining budget and lists recorded retries", async () => {
    const dbPath = tempDb();
    const runId = "run_model_reopen";
    let exec: string;
    const first = newAttempt();
    const second = newAttempt();
    await withStore(dbPath, async (store) => {
      exec = await admitRunning(store, runId, { maxModelAttempts: 3 });
      await store.startModelAttempt(runId, exec, first.started);
      await store.startModelAttempt(runId, exec, second.started);
      await store.recordRetry(runId, exec, {
        authority: "stream-idle",
        count: 1,
        maxRetries: 3,
        delayMs: 750,
      });
      await store.settleModelAttempt(runId, exec, first.fail());
    });

    await withStore(dbPath, async (store) => {
      // Two attempts committed before the crash-equivalent reopen; only one
      // budget slot remains.
      expect(await store.listModelAttempts(runId)).toHaveLength(2);
      const third = newAttempt();
      await store.startModelAttempt(runId, exec!, third.started);
      await expect(
        store.startModelAttempt(runId, exec!, newAttempt().started),
      ).rejects.toThrow(RunLimitError);
      expect(await store.listModelAttempts(runId)).toHaveLength(3);

      // The pre-reopen retry record is intact and inspectable.
      const retries = await store.listRetries(runId);
      expect(retries.map((r) => r.sequence)).toEqual([1]);
      expect(retries[0]?.authority).toBe("stream-idle");
      expect(retries[0]?.count).toBe(1);
      expect(
        Date.parse(retries[0]!.dueAt) - Date.parse(retries[0]!.scheduledAt),
      ).toBe(750);

      // The pre-reopen settlement survived too.
      const attempts = await store.listModelAttempts(runId);
      expect(
        attempts.find((a) => a.attempt.attemptId === first.attemptId)?.attempt
          .lifecycle,
      ).toBe("failed");
    });
  });
});
