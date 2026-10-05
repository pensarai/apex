import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolResultPart } from "ai";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startInferenceAttempt } from "../ai/inference-attempt";
import type { RunModelStore } from "./runModelStore";
import type { RecordedRunSpec } from "./runStore";
import type { RunToolStore } from "./runToolStore";
import { openSqliteRunStore } from "./sqliteRunStore";

// Tool-journal persistence tests through the real SQLite store. They run once
// root wires the v4 schema and the RunToolStore methods into openSqliteRunStore.

type Store = RunModelStore & RunToolStore & { close(): void };

let tempDirs: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("toolstore-db-"), "runs.sqlite");
}

const cwdByRunId = new Map<string, string>();

function spec(runId: string): RecordedRunSpec {
  let cwd = cwdByRunId.get(runId);
  if (!cwd) {
    cwd = tempDir("toolstore-cwd-");
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
  };
}

function evidence() {
  return {
    rootPath: tempDir("toolstore-evroot-"),
    files: [{ path: "findings/a.json", sha256: "0".repeat(64), bytes: 10 }],
  };
}

function textOutput(value: string): ToolResultPart["output"] {
  return { type: "text", value };
}

// Fault injection needs a raw connection — the only place tests reach past
// the public API. createRequire, not dynamic import: vite-node cannot resolve
// the runtime-selected sqlite builtin.
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
  const store = (await openSqliteRunStore(dbPath)) as Store;
  try {
    return await fn(store);
  } finally {
    store.close();
  }
}

async function admitRunning(store: Store, runId: string): Promise<string> {
  const admitted = await store.admit(spec(runId));
  await store.transition(runId, admitted.record.attemptId, "running");
  return admitted.record.attemptId;
}

/** Admit, mark running, enroll the journal, and commit a base context. */
async function journaledRun(
  store: Store,
  runId: string,
): Promise<{ exec: string; revision: number }> {
  const exec = await admitRunning(store, runId);
  await store.initializeToolJournal(runId, exec);
  await store.commitContext(runId, exec, 0, {
    kind: "replace",
    messages: [{ role: "user", content: "first" }],
    system: null,
  });
  return { exec, revision: 1 };
}

function start(
  runId: string,
  exec: string,
  toolCallId: string,
  input: unknown = { url: "http://127.0.0.1:8080/" },
) {
  return {
    runId,
    exec,
    call: {
      toolCallId,
      toolName: "http_request",
      input,
      policy: "external_effect" as const,
    },
  };
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("journal enrollment", () => {
  it("requires the current owner and a running run; is idempotent per owner", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_journal_gate";
      const admitted = await store.admit(spec(runId));

      expect(await store.hasToolJournal(runId)).toBe(false);

      // Admitted (not yet running).
      await expect(
        store.initializeToolJournal(runId, admitted.record.attemptId),
      ).rejects.toThrow(/Run is not running/);

      await store.transition(runId, admitted.record.attemptId, "running");

      // Wrong execution attempt.
      await expect(
        store.initializeToolJournal(
          runId,
          "exec_00000000-0000-4000-8000-000000000000",
        ),
      ).rejects.toThrow(/does not own this run/);

      await store.initializeToolJournal(runId, admitted.record.attemptId);
      expect(await store.hasToolJournal(runId)).toBe(true);

      // Same owner initializes again without change.
      await store.initializeToolJournal(runId, admitted.record.attemptId);
      expect(await store.hasToolJournal(runId)).toBe(true);

      // A foreign attempt fails the owner check before enrollment matters.
      await expect(
        store.initializeToolJournal(
          runId,
          "exec_00000000-0000-4000-8000-000000000001",
        ),
      ).rejects.toThrow(/does not own this run/);
    });
  });

  it("blocks writes when the journal is enrolled by a different execution attempt", async () => {
    const dbPath = tempDb();
    const runId = "run_journal_foreign";
    let exec: string;
    await withStore(dbPath, async (store) => {
      const prepared = await journaledRun(store, runId);
      exec = prepared.exec;
    });

    // Fault injection: the journal claims a different executor while the run
    // record still belongs to the true owner — the legacy-enrollment state a
    // recovery must block on rather than derive from run ownership alone.
    const raw = rawDb(dbPath);
    raw
      .prepare(
        "UPDATE tool_journals SET execution_attempt_id = ? WHERE run_id = ?",
      )
      .run("exec_00000000-0000-4000-8000-0000000000ff", runId);
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.initializeToolJournal(runId, exec)).rejects.toThrow(
        /enrolled by another execution attempt/,
      );
      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_1").call),
      ).rejects.toThrow(/enrolled by another execution attempt/);
      expect(await store.listToolOperations(runId)).toEqual([]);
    });
  });

  it("hasToolJournal never infers a journal from operation rows", async () => {
    const dbPath = tempDb();
    const runId = "run_journal_legacy";
    let exec: string;
    await withStore(dbPath, async (store) => {
      exec = await admitRunning(store, runId);
      // No journal, but simulate an unenrolled legacy writer having produced
      // operation rows — hasToolJournal must still report false.
      const raw = rawDb(dbPath);
      raw.exec(
        "CREATE TABLE IF NOT EXISTS tool_journals (run_id TEXT PRIMARY KEY NOT NULL, version INTEGER NOT NULL, execution_attempt_id TEXT NOT NULL)",
      );
      raw.exec(
        "CREATE TABLE IF NOT EXISTS tool_operations (run_id TEXT NOT NULL, tool_call_id TEXT NOT NULL, sequence INTEGER NOT NULL, record_json TEXT NOT NULL, PRIMARY KEY(run_id, tool_call_id), UNIQUE(run_id, sequence))",
      );
      raw
        .prepare("INSERT INTO tool_operations VALUES (?, ?, ?, ?)")
        .run(runId, "tc_legacy", 1, "{}");
      raw.close();
      expect(await store.hasToolJournal(runId)).toBe(false);
      await expect(
        store.startToolOperation(runId, exec, {
          toolCallId: "tc_1",
          toolName: "http_request",
          input: {},
          policy: "read_only",
        }),
      ).rejects.toThrow(/journal is not initialized/);
    });
  });
});

describe("startToolOperation", () => {
  it("persists a complete operation with context reference, minted id, and monotonic sequence", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_start";
      const { exec } = await journaledRun(store, runId);

      const first = await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      expect(first.created).toBe(true);
      expect(first.operation.operationId).toMatch(/^top_[0-9a-f-]{36}$/);
      expect(first.operation.state).toBe("started");
      expect(first.operation.sequence).toBe(1);
      expect(first.operation.context).toEqual({ epoch: 1, revision: 1 });
      expect(first.operation.input).toEqual({ url: "http://127.0.0.1:8080/" });

      // A later context revision is captured by the next operation.
      await store.commitContext(runId, exec, 1, {
        kind: "append",
        messages: [{ role: "assistant", content: "second" }],
      });
      const second = await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_2").call,
      );
      expect(second.created).toBe(true);
      expect(second.operation.sequence).toBe(2);
      expect(second.operation.context).toEqual({ epoch: 1, revision: 2 });

      const listed = await store.listToolOperations(runId);
      expect(listed.map((op) => op.sequence)).toEqual([1, 2]);
    });
  });

  it("requires an initialized journal and a committed context", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_prereqs";
      const exec = await admitRunning(store, runId);

      // Journal not initialized.
      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_1").call),
      ).rejects.toThrow(/journal is not initialized/);

      await store.initializeToolJournal(runId, exec);

      // No context committed yet.
      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_1").call),
      ).rejects.toThrow(/requires a committed context/);
      expect(await store.listToolOperations(runId)).toEqual([]);
    });
  });

  it("returns the saved operation for an identical duplicate; conflicts reject", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_dup";
      const { exec } = await journaledRun(store, runId);

      const first = await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );

      const again = await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      expect(again.created).toBe(false);
      expect(again.operation).toEqual(first.operation);

      for (const conflicting of [
        { ...start(runId, exec, "tc_1").call, input: { url: "http://other/" } },
        { ...start(runId, exec, "tc_1").call, toolName: "execute_command" },
        { ...start(runId, exec, "tc_1").call, policy: "read_only" as const },
      ]) {
        await expect(
          store.startToolOperation(runId, exec, conflicting),
        ).rejects.toThrow(/different inputs/);
      }

      // The original was never changed by the conflicting attempts.
      const listed = await store.listToolOperations(runId);
      expect(listed).toHaveLength(1);
      expect(listed[0]?.operationId).toBe(first.operation.operationId);
    });
  });

  it("rejects input that JSON cannot represent completely", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_json";
      const { exec } = await journaledRun(store, runId);

      const circular: Record<string, unknown> = { url: "http://x/" };
      circular.self = circular;
      const withFunction = { url: "http://x/", fn: () => {} };
      const withUndefinedValue = { url: "http://x/", extra: undefined };

      for (const bad of [circular, withFunction, withUndefinedValue]) {
        await expect(
          store.startToolOperation(
            runId,
            exec,
            start(runId, exec, "tc_1", bad).call,
          ),
        ).rejects.toThrow();
      }
      expect(await store.listToolOperations(runId)).toEqual([]);
    });
  });

  it("rejects a non-owner or non-running run", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_owner";
      const { exec } = await journaledRun(store, runId);

      await expect(
        store.startToolOperation(
          runId,
          "exec_00000000-0000-4000-8000-000000000000",
          start(runId, exec, "tc_1").call,
        ),
      ).rejects.toThrow(/does not own this run/);

      await store.transition(runId, exec, "completed");
      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_1").call),
      ).rejects.toThrow(/Run is not running/);
    });
  });
});

describe("settleToolOperation", () => {
  it("settles started -> settled with validated output and evidence", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_settle";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );

      const ev = evidence();
      await store.settleToolOperation(
        runId,
        exec,
        "tc_1",
        textOutput("done"),
        ev,
      );

      const listed = await store.listToolOperations(runId);
      expect(listed[0]?.state).toBe("settled");
      expect(listed[0]?.output).toEqual(textOutput("done"));
      expect(listed[0]?.evidence).toEqual(ev);

      // Byte-identical re-settlement is idempotent.
      await store.settleToolOperation(
        runId,
        exec,
        "tc_1",
        textOutput("done"),
        ev,
      );
      expect((await store.listToolOperations(runId))[0]?.state).toBe("settled");
    });
  });

  it("rejects a different output or evidence for a settled operation", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_resettle";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      const ev = evidence();
      await store.settleToolOperation(
        runId,
        exec,
        "tc_1",
        textOutput("done"),
        ev,
      );

      await expect(
        store.settleToolOperation(runId, exec, "tc_1", textOutput("other"), ev),
      ).rejects.toThrow(/different outcome/);
      await expect(
        store.settleToolOperation(runId, exec, "tc_1", textOutput("done"), {
          ...ev,
          files: [{ path: "b.txt", sha256: "1".repeat(64), bytes: 2 }],
        }),
      ).rejects.toThrow(/different outcome/);
      expect((await store.listToolOperations(runId))[0]?.state).toBe("settled");
    });
  });

  it("rejects output and evidence that fail shape validation", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_shapes";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );

      // Raw string is not a ToolResultOutput.
      await expect(
        store.settleToolOperation(
          runId,
          exec,
          "tc_1",
          "raw" as never,
          evidence(),
        ),
      ).rejects.toThrow();
      await expect(
        store.settleToolOperation(
          runId,
          exec,
          "tc_1",
          { type: "json", value: { omitted: undefined } },
          evidence(),
        ),
      ).rejects.toThrow(/output is not completely JSON-serializable/);
      const badEvidence = [
        { ...evidence(), rootPath: "relative/root" },
        {
          ...evidence(),
          files: [{ path: "../escape.txt", sha256: "0".repeat(64), bytes: 1 }],
        },
        {
          ...evidence(),
          files: [{ path: "a.txt", sha256: "nothex", bytes: 1 }],
        },
      ];
      for (const ev of badEvidence) {
        await expect(
          store.settleToolOperation(
            runId,
            exec,
            "tc_1",
            textOutput("done"),
            ev,
          ),
        ).rejects.toThrow();
      }

      // Nothing settled; the operation stays started.
      expect((await store.listToolOperations(runId))[0]?.state).toBe("started");
    });
  });

  it("rejects settling an operation marked outcome_unknown or never started", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_unknown_gate";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );

      await expect(
        store.settleToolOperation(
          runId,
          exec,
          "tc_missing",
          textOutput("x"),
          evidence(),
        ),
      ).rejects.toThrow(/no committed start/);

      await store.markToolOutcomeUnknown(runId, exec, "tc_1");
      await expect(
        store.settleToolOperation(
          runId,
          exec,
          "tc_1",
          textOutput("done"),
          evidence(),
        ),
      ).rejects.toThrow(/already recorded as unknown/);
      expect((await store.listToolOperations(runId))[0]?.state).toBe(
        "outcome_unknown",
      );
    });
  });

  it("merges settled evidence into the run's current snapshot, keeping per-operation receipts", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_snapshot";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_2").call,
      );

      const rootPath = tempDir("toolstore-snaproot-");
      const first = {
        rootPath,
        files: [
          { path: "findings/one.json", sha256: "1".repeat(64), bytes: 11 },
        ],
      };
      const second = {
        rootPath,
        files: [
          { path: "findings/two.json", sha256: "2".repeat(64), bytes: 22 },
        ],
      };

      await store.settleToolOperation(
        runId,
        exec,
        "tc_1",
        textOutput("one"),
        first,
      );
      await store.settleToolOperation(
        runId,
        exec,
        "tc_2",
        textOutput("two"),
        second,
      );

      // The current snapshot holds every settled ref merged by path.
      const snapshot = await store.getEvidence(runId);
      expect(snapshot?.rootPath).toBe(rootPath);
      expect(snapshot?.files).toEqual([...first.files, ...second.files]);

      // Per-operation evidence stays the receipt history, not the union.
      const listed = await store.listToolOperations(runId);
      expect(listed.find((op) => op.toolCallId === "tc_1")?.evidence).toEqual(
        first,
      );
      expect(listed.find((op) => op.toolCallId === "tc_2")?.evidence).toEqual(
        second,
      );
    });
  });

  it("rolls the settlement back when the evidence snapshot update fails", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_snapshot_rollback";
      const admitted = await store.admit(spec(runId));
      const exec = admitted.record.attemptId;
      await store.transition(runId, exec, "running");
      await store.initializeToolJournal(runId, exec);

      // Fix the run's evidence location via the context commit's evidence.
      const firstRoot = tempDir("toolstore-firstroot-");
      await store.commitContext(
        runId,
        exec,
        0,
        {
          kind: "replace",
          messages: [{ role: "user", content: "first" }],
          system: null,
        },
        { rootPath: firstRoot, files: [] },
      );

      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );

      // A settlement naming a different evidence root must fail through the
      // snapshot writer and take the settlement down with it.
      const movedRoot = {
        ...evidence(),
        rootPath: tempDir("toolstore-movedroot-"),
      };
      await expect(
        store.settleToolOperation(
          runId,
          exec,
          "tc_1",
          textOutput("done"),
          movedRoot,
        ),
      ).rejects.toThrow();

      const listed = await store.listToolOperations(runId);
      expect(listed[0]?.state).toBe("started");
      expect(listed[0]?.output).toBeUndefined();
      expect((await store.getEvidence(runId))?.files).toEqual([]);
    });
  });
});

describe("markToolOutcomeUnknown", () => {
  it("moves started -> outcome_unknown idempotently; never relabels settled", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_mark";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_2").call,
      );

      await store.markToolOutcomeUnknown(runId, exec, "tc_1");
      await store.markToolOutcomeUnknown(runId, exec, "tc_1");

      await store.settleToolOperation(
        runId,
        exec,
        "tc_2",
        textOutput("done"),
        evidence(),
      );

      await expect(
        store.markToolOutcomeUnknown(runId, exec, "tc_2"),
      ).rejects.toThrow(/already settled/);

      const listed = await store.listToolOperations(runId);
      expect(listed.find((op) => op.toolCallId === "tc_1")?.state).toBe(
        "outcome_unknown",
      );
      expect(listed.find((op) => op.toolCallId === "tc_2")?.state).toBe(
        "settled",
      );
    });
  });
});

describe("list validation and corruption", () => {
  it("orders by sequence and survives reopen", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_list";
    const ids = ["tc_a", "tc_b", "tc_c"];
    await withStore(dbPath, async (store) => {
      const { exec } = await journaledRun(store, runId);
      for (const id of ids) {
        await store.startToolOperation(
          runId,
          exec,
          start(runId, exec, id).call,
        );
      }
      await store.settleToolOperation(
        runId,
        exec,
        "tc_b",
        textOutput("done"),
        evidence(),
      );
      await store.markToolOutcomeUnknown(runId, exec, "tc_c");
    });

    await withStore(dbPath, async (store) => {
      const listed = await store.listToolOperations(runId);
      expect(listed.map((op) => op.toolCallId)).toEqual(ids);
      expect(listed.map((op) => op.sequence)).toEqual([1, 2, 3]);
      expect(listed.map((op) => op.state)).toEqual([
        "started",
        "settled",
        "outcome_unknown",
      ]);
    });
  });

  it("read-only inspection still works after the run is terminal; writes reject", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_tool_terminal_read";
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      await store.settleToolOperation(
        runId,
        exec,
        "tc_1",
        textOutput("done"),
        evidence(),
      );
      await store.transition(runId, exec, "completed");

      expect(await store.hasToolJournal(runId)).toBe(true);
      expect(
        (await store.listToolOperations(runId)).map((op) => op.state),
      ).toEqual(["settled"]);

      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_2").call),
      ).rejects.toThrow(/Run is not running/);
    });
  });

  it("reports corrupt operation rows explicitly, never repairing them", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_corrupt";
    await withStore(dbPath, async (store) => {
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
    });

    const raw = rawDb(dbPath);
    raw
      .prepare(
        "UPDATE tool_operations SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
      )
      .run("{not json", runId, "tc_1");
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.listToolOperations(runId)).rejects.toThrow();
      // A duplicate start must not "repair" the damaged row into fresh state.
      await expect(
        store.startToolOperation(
          runId,
          "exec_placeholder",
          start(runId, "exec_placeholder", "tc_1").call,
        ),
      ).rejects.toThrow();
    });

    const raw2 = rawDb(dbPath);
    const row = raw2
      .prepare(
        "SELECT record_json FROM tool_operations WHERE run_id = ? AND tool_call_id = ?",
      )
      .get(runId, "tc_1") as { record_json: string };
    raw2.close();
    expect(row.record_json).toBe("{not json");
  });

  it("reports a row whose record key no longer matches its stored identity", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_keymatch";
    await withStore(dbPath, async (store) => {
      const { exec } = await journaledRun(store, runId);
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_2").call,
      );
    });

    // Move tc_2's record into tc_1's row: parse succeeds but the record's
    // toolCallId/sequence contradict the row keys.
    const raw = rawDb(dbPath);
    const other = raw
      .prepare(
        "SELECT record_json FROM tool_operations WHERE run_id = ? AND tool_call_id = ?",
      )
      .get(runId, "tc_2") as { record_json: string };
    raw
      .prepare(
        "UPDATE tool_operations SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
      )
      .run(other.record_json, runId, "tc_1");
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.listToolOperations(runId)).rejects.toThrow(
        /identity is corrupt/,
      );
    });
  });
});

describe("write failures roll back", () => {
  it("a trigger-injected insert failure leaves no operation", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_trigger";
    let exec: string;
    await withStore(dbPath, async (store) => {
      const prepared = await journaledRun(store, runId);
      exec = prepared.exec;
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_tool_insert BEFORE INSERT ON tool_operations " +
        "BEGIN SELECT RAISE(ABORT, 'injected tool operation failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(
        store.startToolOperation(
          runId,
          exec!,
          start(runId, exec!, "tc_1").call,
        ),
      ).rejects.toThrow();
      expect(await store.listToolOperations(runId)).toEqual([]);
    });
  });

  it("rolls the settlement back when the evidence snapshot writer fails", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_evidence_trigger";
    let exec: string;
    await withStore(dbPath, async (store) => {
      const prepared = await journaledRun(store, runId);
      exec = prepared.exec;
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_1").call,
      );
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_ev_insert BEFORE INSERT ON run_evidence " +
        "BEGIN SELECT RAISE(ABORT, 'injected evidence write failure'); END",
    );
    raw.exec(
      "CREATE TRIGGER reject_ev_update BEFORE UPDATE ON run_evidence " +
        "BEGIN SELECT RAISE(ABORT, 'injected evidence write failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(
        store.settleToolOperation(
          runId,
          exec,
          "tc_1",
          textOutput("done"),
          evidence(),
        ),
      ).rejects.toThrow();

      // The settlement and the snapshot update rolled back together.
      const listed = await store.listToolOperations(runId);
      expect(listed[0]?.state).toBe("started");
      expect(listed[0]?.output).toBeUndefined();
      expect(await store.getEvidence(runId)).toBeUndefined();
    });
  });
});

describe("mutated records are rejected on read", () => {
  it("rejects settled records missing output or evidence, and unsettled records carrying them", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_shape_mutations";
    let exec: string;
    let startedJson: string;
    let settledJson: string;
    await withStore(dbPath, async (store) => {
      const prepared = await journaledRun(store, runId);
      exec = prepared.exec;
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_started").call,
      );
      await store.startToolOperation(
        runId,
        exec,
        start(runId, exec, "tc_settled").call,
      );
      await store.settleToolOperation(
        runId,
        exec,
        "tc_settled",
        textOutput("done"),
        evidence(),
      );
      const raw = rawDb(dbPath);
      startedJson = (
        raw
          .prepare(
            "SELECT record_json FROM tool_operations WHERE run_id = ? AND tool_call_id = ?",
          )
          .get(runId, "tc_started") as { record_json: string }
      ).record_json;
      settledJson = (
        raw
          .prepare(
            "SELECT record_json FROM tool_operations WHERE run_id = ? AND tool_call_id = ?",
          )
          .get(runId, "tc_settled") as { record_json: string }
      ).record_json;
      raw.close();
    });

    const mutate = async (toolCallId: string, json: string) => {
      const raw = rawDb(dbPath);
      raw
        .prepare(
          "UPDATE tool_operations SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
        )
        .run(json, runId, toolCallId);
      raw.close();
      await withStore(dbPath, async (store) => {
        await expect(store.listToolOperations(runId)).rejects.toThrow();
      });
      const raw2 = rawDb(dbPath);
      raw2
        .prepare(
          "UPDATE tool_operations SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
        )
        .run(
          toolCallId === "tc_settled" ? settledJson! : startedJson!,
          runId,
          toolCallId,
        );
      raw2.close();
    };

    const settled = JSON.parse(settledJson!) as Record<string, unknown>;
    const started = JSON.parse(startedJson!) as Record<string, unknown>;
    const ev = evidence();

    // Settled without output; settled without evidence.
    await mutate(
      "tc_settled",
      JSON.stringify({ ...settled, output: undefined }),
    );
    await mutate(
      "tc_settled",
      JSON.stringify({ ...settled, evidence: undefined }),
    );

    // Unsettled records carrying invented output/evidence.
    await mutate(
      "tc_started",
      JSON.stringify({ ...started, output: textOutput("invented") }),
    );
    await mutate("tc_started", JSON.stringify({ ...started, evidence: ev }));

    // Missing input key.
    const { input: _input, ...withoutInput } = settled;
    await mutate("tc_settled", JSON.stringify(withoutInput));

    // After restoring, the records read cleanly again.
    await withStore(dbPath, async (store) => {
      const listed = await store.listToolOperations(runId);
      expect(listed.map((op) => op.state).sort()).toEqual([
        "settled",
        "started",
      ]);
    });
  });

  it("rejects corrupt or future-version journal rows in every reader", async () => {
    const dbPath = tempDb();
    const runId = "run_tool_journal_corrupt";
    let exec: string;
    await withStore(dbPath, async (store) => {
      const prepared = await journaledRun(store, runId);
      exec = prepared.exec;
    });

    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE tool_journals SET version = ? WHERE run_id = ?")
      .run(2, runId);
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.hasToolJournal(runId)).rejects.toThrow(
        /unsupported version/,
      );
      await expect(store.initializeToolJournal(runId, exec)).rejects.toThrow(
        /unsupported version/,
      );
      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_1").call),
      ).rejects.toThrow(/unsupported version/);
    });

    const raw2 = rawDb(dbPath);
    raw2
      .prepare("UPDATE tool_journals SET version = ? WHERE run_id = ?")
      .run(1, runId);
    raw2
      .prepare(
        "UPDATE tool_journals SET execution_attempt_id = ? WHERE run_id = ?",
      )
      .run("not-an-attempt-id", runId);
    raw2.close();

    await withStore(dbPath, async (store) => {
      await expect(store.hasToolJournal(runId)).rejects.toThrow(/corrupt/);
      await expect(store.initializeToolJournal(runId, exec)).rejects.toThrow(
        /corrupt/,
      );
      await expect(
        store.startToolOperation(runId, exec, start(runId, exec, "tc_1").call),
      ).rejects.toThrow(/corrupt/);
    });
  });
});

describe("v3 databases migrate to v4 preserving prior state", () => {
  it("migrates a genuine v3 database and continues tool journaling", async () => {
    // Seed through the real store, then rebuild the file as exact v3 shape:
    // runs + run_context + run_evidence + model tables only.
    const seedDb = tempDb();
    const runId = "run_tool_migrate";
    const rootPath = tempDir("toolstore-migrate-evroot-");
    let exec: string;
    const modelHandle = startInferenceAttempt({
      operationKind: "agent.stream",
      requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
    });
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
          files: [{ path: "a.txt", sha256: "3".repeat(64), bytes: 3 }],
        },
      );
      await store.startModelAttempt(runId, exec, modelHandle.started);
    });

    const rawSeed = rawDb(seedDb);
    const recordJson = (
      rawSeed
        .prepare("SELECT record_json FROM runs WHERE run_id = ?")
        .get(runId) as { record_json: string }
    ).record_json;
    const contextRows = rawSeed
      .prepare(
        "SELECT revision, epoch, change_json FROM run_context WHERE run_id = ? ORDER BY revision",
      )
      .all(runId) as Array<{
      revision: number;
      epoch: number;
      change_json: string;
    }>;
    const evidenceJson = (
      rawSeed
        .prepare("SELECT evidence_json FROM run_evidence WHERE run_id = ?")
        .get(runId) as { evidence_json: string }
    ).evidence_json;
    const modelRows = rawSeed
      .prepare(
        "SELECT attempt_id, record_json FROM model_attempts WHERE run_id = ?",
      )
      .all(runId) as Array<{ attempt_id: string; record_json: string }>;
    rawSeed.close();

    const dbPath = tempDb();
    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TABLE runs (run_id TEXT PRIMARY KEY NOT NULL, record_json TEXT NOT NULL)",
    );
    raw
      .prepare("INSERT INTO runs (run_id, record_json) VALUES (?, ?)")
      .run(runId, recordJson);
    raw.exec(`
      CREATE TABLE run_context (
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        revision INTEGER NOT NULL CHECK(revision > 0),
        epoch INTEGER NOT NULL CHECK(epoch > 0),
        change_json TEXT NOT NULL,
        PRIMARY KEY(run_id, revision)
      );
    `);
    for (const row of contextRows) {
      raw
        .prepare("INSERT INTO run_context VALUES (?, ?, ?, ?)")
        .run(runId, row.revision, row.epoch, row.change_json);
    }
    raw.exec(`
      CREATE TABLE run_evidence (
        run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(run_id),
        evidence_json TEXT NOT NULL
      );
    `);
    raw
      .prepare("INSERT INTO run_evidence (run_id, evidence_json) VALUES (?, ?)")
      .run(runId, evidenceJson);
    raw.exec(`
      CREATE TABLE model_attempts (
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        attempt_id TEXT NOT NULL,
        record_json TEXT NOT NULL,
        PRIMARY KEY(run_id, attempt_id)
      );
    `);
    for (const row of modelRows) {
      raw
        .prepare("INSERT INTO model_attempts VALUES (?, ?, ?)")
        .run(runId, row.attempt_id, row.record_json);
    }
    raw.exec("PRAGMA application_id = 0x41505258");
    raw.exec("PRAGMA user_version = 3");
    raw.close();

    await withStore(dbPath, async (store) => {
      // Prior run, context, evidence, and model attempts survive the migration.
      expect((await store.get(runId))?.attemptId).toBe(exec);
      const context = await store.getContext(runId);
      expect(context?.messages).toEqual([{ role: "user", content: "first" }]);
      expect((await store.getEvidence(runId))?.files).toEqual([
        { path: "a.txt", sha256: "3".repeat(64), bytes: 3 },
      ]);
      expect(await store.listModelAttempts(runId)).toHaveLength(1);

      // v3 had no tool journal; migration starts it empty but functional.
      expect(await store.hasToolJournal(runId)).toBe(false);
      await store.initializeToolJournal(runId, exec!);
      const op = await store.startToolOperation(
        runId,
        exec!,
        start(runId, exec!, "tc_1").call,
      );
      expect(op.created).toBe(true);
      // Settlement evidence must name the preserved snapshot's root.
      await store.settleToolOperation(
        runId,
        exec!,
        "tc_1",
        textOutput("done"),
        {
          rootPath,
          files: [
            { path: "findings/b.json", sha256: "4".repeat(64), bytes: 4 },
          ],
        },
      );
      const settled = (await store.listToolOperations(runId))[0];
      expect(settled?.state).toBe("settled");
      expect((await store.getEvidence(runId))?.files).toEqual([
        { path: "a.txt", sha256: "3".repeat(64), bytes: 3 },
        { path: "findings/b.json", sha256: "4".repeat(64), bytes: 4 },
      ]);
    });
  });
});
