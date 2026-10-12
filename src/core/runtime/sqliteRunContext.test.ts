import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { RecordedRunSpec } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

let tempDirs: string[] = [];
let holdChild: ReturnType<typeof spawn> | undefined;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("runcontext-db-"), "runs.sqlite");
}

const cwdByRunId = new Map<string, string>();

function spec(runId: string): RecordedRunSpec {
  let cwd = cwdByRunId.get(runId);
  if (!cwd) {
    cwd = tempDir("runcontext-cwd-");
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

function userMsg(text: string): ModelMessage {
  return { role: "user", content: text };
}

function assistantMsg(text: string): ModelMessage {
  return { role: "assistant", content: [{ type: "text", text }] };
}

function toolResultMsg(toolCallId: string, value: string): ModelMessage {
  return {
    role: "tool",
    content: [
      {
        type: "tool-result",
        toolCallId,
        toolName: "http_request",
        output: { type: "text", value },
      },
    ],
  };
}

// Fault injection and v1-fixture construction need a raw connection — the only
// place tests reach past the public API. createRequire, not dynamic import:
// vite-node cannot resolve the runtime-selected sqlite builtin.
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

async function admitRunning(store: Store, runId: string): Promise<string> {
  const admitted = await store.admit(spec(runId));
  await store.transition(runId, admitted.record.attemptId, "running");
  return admitted.record.attemptId;
}

/** A genuine B1 database: runs table only, user_version 1, one real record. */
async function b1Database(recordJson: string, runId: string): Promise<string> {
  const dbPath = tempDb();
  const raw = rawDb(dbPath);
  raw.exec(
    "CREATE TABLE runs (run_id TEXT PRIMARY KEY NOT NULL, record_json TEXT NOT NULL)",
  );
  raw
    .prepare("INSERT INTO runs (run_id, record_json) VALUES (?, ?)")
    .run(runId, recordJson);
  raw.exec("PRAGMA application_id = 0x41505258");
  raw.exec("PRAGMA user_version = 1");
  raw.close();
  return dbPath;
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  if (holdChild?.killed === false && holdChild.exitCode === null) {
    holdChild.kill("SIGKILL");
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("revision and epoch rules", () => {
  it("initial replace at expectedRevision 0 opens epoch 1 revision 1", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_initial";
      const attemptId = await admitRunning(store, runId);

      const result = await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: "system prompt",
      });

      expect(result).toEqual({ epoch: 1, revision: 1 });
      const context = await store.getContext(runId);
      expect(context?.epoch).toBe(1);
      expect(context?.revision).toBe(1);
    });
  });

  it("append stays in the epoch and bumps the revision; replace bumps both", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_ladder";
      const attemptId = await admitRunning(store, runId);

      const first = await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: "system prompt",
      });
      expect(first).toEqual({ epoch: 1, revision: 1 });

      const appended = await store.commitContext(
        runId,
        attemptId,
        first.revision,
        { kind: "append", messages: [assistantMsg("second")] },
      );
      expect(appended).toEqual({ epoch: 1, revision: 2 });

      const appendedAgain = await store.commitContext(
        runId,
        attemptId,
        appended.revision,
        { kind: "append", messages: [toolResultMsg("tc_1", "ok")] },
      );
      expect(appendedAgain).toEqual({ epoch: 1, revision: 3 });

      // Revision is global-monotonic: a replace opens the next epoch and
      // still advances the revision (contract: replace → epoch+1, rev+1).
      const replaced = await store.commitContext(
        runId,
        attemptId,
        appendedAgain.revision,
        { kind: "replace", messages: [userMsg("compacted")], system: null },
      );
      expect(replaced).toEqual({ epoch: 2, revision: 4 });
    });
  });

  it("replace carries its own system; append preserves the epoch's system", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_system";
      const attemptId = await admitRunning(store, runId);

      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: "original system",
      });
      await store.commitContext(runId, attemptId, 1, {
        kind: "append",
        messages: [assistantMsg("second")],
      });
      expect((await store.getContext(runId))?.system).toBe("original system");

      await store.commitContext(runId, attemptId, 2, {
        kind: "replace",
        messages: [userMsg("compacted")],
        system: "compacted system",
      });
      expect((await store.getContext(runId))?.system).toBe("compacted system");
    });
  });

  it("getContext returns ordered base + deltas; undefined with no context", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_order";
      const attemptId = await admitRunning(store, runId);

      expect(await store.getContext(runId)).toBeUndefined();

      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first"), assistantMsg("second")],
        system: "system prompt",
      });
      await store.commitContext(runId, attemptId, 1, {
        kind: "append",
        messages: [toolResultMsg("tc_1", "ok"), userMsg("third")],
      });

      const context = await store.getContext(runId);
      expect(context?.messages).toEqual([
        userMsg("first"),
        assistantMsg("second"),
        toolResultMsg("tc_1", "ok"),
        userMsg("third"),
      ]);
    });
  });

  it("persists order, epoch, and system across reopen", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_reopen";
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: "system prompt",
      });
      await store.commitContext(runId, attemptId, 1, {
        kind: "append",
        messages: [assistantMsg("second")],
      });
    });

    await withStore(dbPath, async (store) => {
      const context = await store.getContext(runId);
      expect(context?.epoch).toBe(1);
      expect(context?.revision).toBe(2);
      expect(context?.system).toBe("system prompt");
      expect(context?.messages).toEqual([
        userMsg("first"),
        assistantMsg("second"),
      ]);

      const next = await store.commitContext(runId, attemptId!, 2, {
        kind: "append",
        messages: [userMsg("third")],
      });
      expect(next).toEqual({ epoch: 1, revision: 3 });
    });
  });
});

describe("ownership and admission-state gating", () => {
  it("rejects a commit from an attempt that does not own the run", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_owner";
      await admitRunning(store, runId);

      await expect(
        store.commitContext(runId, "exec_not_the_owner", 0, {
          kind: "replace",
          messages: [userMsg("first")],
          system: null,
        }),
      ).rejects.toThrow();
      expect(await store.getContext(runId)).toBeUndefined();
    });
  });

  it("rejects commits before the run is running (admitted status)", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_admitted";
      const admitted = await store.admit(spec(runId));

      await expect(
        store.commitContext(runId, admitted.record.attemptId, 0, {
          kind: "replace",
          messages: [userMsg("first")],
          system: null,
        }),
      ).rejects.toThrow();
    });
  });

  it("rejects commits after the run reached a terminal status", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_completed";
      const attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: null,
      });
      await store.transition(runId, attemptId, "completed");

      await expect(
        store.commitContext(runId, attemptId, 1, {
          kind: "append",
          messages: [userMsg("late")],
        }),
      ).rejects.toThrow();

      // The pre-completion context is still readable after completion.
      expect((await store.getContext(runId))?.revision).toBe(1);
    });
  });

  it("rejects append without an established base context", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_no_base";
      const attemptId = await admitRunning(store, runId);

      await expect(
        store.commitContext(runId, attemptId, 0, {
          kind: "append",
          messages: [userMsg("orphan")],
        }),
      ).rejects.toThrow();
      expect(await store.getContext(runId)).toBeUndefined();
    });
  });
});

describe("optimistic concurrency", () => {
  it("rejects a stale expectedRevision from a rival connection", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_stale";
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
    });

    const a = await openSqliteRunStore(dbPath);
    const b = await openSqliteRunStore(dbPath);
    try {
      await a.commitContext(runId, attemptId!, 0, {
        kind: "replace",
        messages: [userMsg("winner")],
        system: null,
      });

      await expect(
        b.commitContext(runId, attemptId!, 0, {
          kind: "replace",
          messages: [userMsg("loser")],
          system: null,
        }),
      ).rejects.toThrow(/conflict/i);

      const context = await b.getContext(runId);
      expect(context?.revision).toBe(1);
      expect(context?.messages).toEqual([userMsg("winner")]);
    } finally {
      a.close();
      b.close();
    }
  });

  it("rejects a stale expectedRevision after reopen", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_stale_reopen";
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: null,
      });
    });

    await withStore(dbPath, async (store) => {
      await expect(
        store.commitContext(runId, attemptId!, 0, {
          kind: "append",
          messages: [userMsg("stale")],
        }),
      ).rejects.toThrow(/conflict/i);
      expect((await store.getContext(runId))?.revision).toBe(1);
    });
  });
});

describe("invalid input is rejected before any write", () => {
  it("rejects non-array messages", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_invalid";
      const attemptId = await admitRunning(store, runId);

      await expect(
        store.commitContext(runId, attemptId, 0, {
          kind: "replace",
          messages: "not an array" as never,
          system: null,
        }),
      ).rejects.toThrow();
      expect(await store.getContext(runId)).toBeUndefined();
    });
  });

  it("rejects messages that are not valid ModelMessages", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_invalid";
      const attemptId = await admitRunning(store, runId);

      await expect(
        store.commitContext(runId, attemptId, 0, {
          kind: "replace",
          messages: [{ role: "spaceship", content: "beep" } as never],
          system: null,
        }),
      ).rejects.toThrow();
      await expect(
        store.commitContext(runId, attemptId, 0, {
          kind: "replace",
          messages: [null as never],
          system: null,
        }),
      ).rejects.toThrow();
      expect(await store.getContext(runId)).toBeUndefined();
    });
  });

  it("rejects a tool-result message whose output is not a tool result shape", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_invalid_output";
      const attemptId = await admitRunning(store, runId);

      await expect(
        store.commitContext(runId, attemptId, 0, {
          kind: "replace",
          messages: [
            {
              role: "tool",
              content: [
                {
                  type: "tool-result",
                  toolCallId: "tc_1",
                  toolName: "http_request",
                  output: "raw string is not a ToolResultOutput",
                },
              ],
            } as never,
          ],
          system: null,
        }),
      ).rejects.toThrow();
      expect(await store.getContext(runId)).toBeUndefined();
    });
  });

  it("rejects a non-serializable payload", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_circular";
      const attemptId = await admitRunning(store, runId);
      const circular = { role: "user" } as never;
      Object.assign(circular, { self: circular });

      await expect(
        store.commitContext(runId, attemptId, 0, {
          kind: "replace",
          messages: [circular],
          system: null,
        }),
      ).rejects.toThrow();
      expect(await store.getContext(runId)).toBeUndefined();
    });
  });
});

describe("damaged rows are explicit and never silently repaired", () => {
  it("reports corrupt context JSON explicitly and leaves it untouched", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_corrupt";
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: null,
      });
    });

    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE run_context SET change_json = ? WHERE run_id = ?")
      .run("{not json", runId);
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.getContext(runId)).rejects.toThrow();
      await expect(
        store.commitContext(runId, attemptId!, 1, {
          kind: "append",
          messages: [userMsg("repair attempt")],
        }),
      ).rejects.toThrow();
    });

    // The failed commit did not repair the damaged row into fresh state.
    const raw2 = rawDb(dbPath);
    const row = raw2
      .prepare("SELECT change_json FROM run_context WHERE run_id = ?")
      .get(runId) as { change_json: string };
    raw2.close();
    expect(row.change_json).toBe("{not json");
  });

  it("reports schema-invalid context rows explicitly", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_schema";
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: null,
      });
    });

    // Valid JSON that violates the context change schema (missing messages).
    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE run_context SET change_json = ? WHERE run_id = ?")
      .run(JSON.stringify({ kind: "append" }), runId);
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.getContext(runId)).rejects.toThrow();
      await expect(
        store.commitContext(runId, attemptId!, 1, {
          kind: "append",
          messages: [userMsg("blocked")],
        }),
      ).rejects.toThrow();
    });
  });

  it("reports a base row that no longer holds a replacement", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_base_lost";
    await withStore(dbPath, async (store) => {
      const attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: null,
      });
    });

    // Overwrite the base row with a valid append change — the epoch's first
    // row must be a replacement, so reconstruction must refuse.
    const raw = rawDb(dbPath);
    raw
      .prepare(
        "UPDATE run_context SET change_json = ? WHERE run_id = ? AND revision = 1",
      )
      .run(
        JSON.stringify({ kind: "append", messages: [userMsg("not a base")] }),
        runId,
      );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.getContext(runId)).rejects.toThrow();
    });
  });
});

describe("evidence snapshots commit atomically with context", () => {
  // Distinct, valid 64-char lowercase-hex digests (schema-validated).
  const sha = (n: number) => n.toString(16).padStart(64, "0");

  function evidence(rootPath: string, files: Array<[string, number]>) {
    return {
      rootPath,
      files: files.map(([p, n]) => ({ path: p, sha256: sha(n), bytes: n })),
    };
  }

  it("persists evidence refs and merges by path across reopen", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_ev_merge";
    const rootPath = tempDir("runcontext-evroot-");
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(
        runId,
        attemptId,
        0,
        { kind: "replace", messages: [userMsg("first")], system: null },
        evidence(rootPath, [
          ["findings/a.json", 10],
          ["pocs/b.txt", 20],
        ]),
      );
      await store.commitContext(
        runId,
        attemptId,
        1,
        { kind: "append", messages: [assistantMsg("second")] },
        // Same digest for a.json — an exact re-commit must not perturb the ref.
        evidence(rootPath, [
          ["findings/a.json", 10],
          ["evidence/c.md", 30],
        ]),
      );
    });

    await withStore(dbPath, async (store) => {
      const snapshot = await store.getEvidence(runId);
      expect(snapshot?.rootPath).toBe(rootPath);
      expect(snapshot?.files).toEqual([
        { path: "evidence/c.md", sha256: sha(30), bytes: 30 },
        { path: "findings/a.json", sha256: sha(10), bytes: 10 },
        { path: "pocs/b.txt", sha256: sha(20), bytes: 20 },
      ]);

      // A later digest for the same path replaces only that ref; a file the
      // newer commits stopped listing stays recorded so missing-artifact
      // inspection can still run against its last known digest.
      await store.commitContext(
        runId,
        attemptId!,
        2,
        { kind: "append", messages: [userMsg("third")] },
        evidence(rootPath, [["findings/a.json", 11]]),
      );
      expect((await store.getEvidence(runId))?.files).toEqual([
        { path: "evidence/c.md", sha256: sha(30), bytes: 30 },
        { path: "findings/a.json", sha256: sha(11), bytes: 11 },
        { path: "pocs/b.txt", sha256: sha(20), bytes: 20 },
      ]);
    });
  });

  it("rejects a changed rootPath and rolls the context revision back", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_ev_root";
    await withStore(dbPath, async (store) => {
      const attemptId = await admitRunning(store, runId);
      await store.commitContext(
        runId,
        attemptId,
        0,
        { kind: "replace", messages: [userMsg("first")], system: null },
        evidence("/original/session/root", [["a.txt", 1]]),
      );

      await expect(
        store.commitContext(
          runId,
          attemptId,
          1,
          { kind: "append", messages: [userMsg("second")] },
          evidence("/moved/session/root", [["a.txt", 1]]),
        ),
      ).rejects.toThrow(/location changed/);

      // The whole commit rolled back: the context is still revision 1 and the
      // message delta did not land.
      const context = await store.getContext(runId);
      expect(context?.revision).toBe(1);
      expect(context?.messages).toEqual([userMsg("first")]);
      expect((await store.getEvidence(runId))?.rootPath).toBe(
        "/original/session/root",
      );
    });
  });

  it("rolls the context back when the evidence insert fails", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_ev_trigger";
    const rootPath = tempDir("runcontext-evroot-");
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(
        runId,
        attemptId,
        0,
        { kind: "replace", messages: [userMsg("first")], system: null },
        evidence(rootPath, [["a.txt", 1]]),
      );
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_ev_write BEFORE INSERT ON run_evidence " +
        "BEGIN SELECT RAISE(ABORT, 'injected evidence write failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(
        store.commitContext(
          runId,
          attemptId!,
          1,
          { kind: "append", messages: [userMsg("blocked")] },
          evidence(rootPath, [["b.txt", 2]]),
        ),
      ).rejects.toThrow();

      // One transaction: the context delta and the evidence update both
      // rolled back together.
      const context = await store.getContext(runId);
      expect(context?.revision).toBe(1);
      expect(context?.messages).toEqual([userMsg("first")]);
      const snapshot = await store.getEvidence(runId);
      expect(snapshot?.files).toEqual([
        { path: "a.txt", sha256: sha(1), bytes: 1 },
      ]);
    });
  });

  it("rejects invalid evidence refs before any write", async () => {
    await withStore(tempDb(), async (store) => {
      const runId = "run_ctx_ev_invalid";
      const attemptId = await admitRunning(store, runId);

      const cases: Array<Record<string, unknown>> = [
        { rootPath: "relative/root", files: [] },
        {
          rootPath: "/abs",
          files: [{ path: "/abs/escape.txt", sha256: sha(1), bytes: 1 }],
        },
        {
          rootPath: "/abs",
          files: [{ path: "../escape.txt", sha256: sha(1), bytes: 1 }],
        },
        {
          rootPath: "/abs",
          files: [{ path: "ok.txt", sha256: "nothex", bytes: 1 }],
        },
        {
          rootPath: "/abs",
          files: [{ path: "ok.txt", sha256: sha(1), bytes: -1 }],
        },
        {
          rootPath: "/abs",
          files: [{ path: "ok.txt", sha256: sha(1), bytes: 1.5 }],
        },
      ];
      for (const bad of cases) {
        await expect(
          store.commitContext(
            runId,
            attemptId,
            0,
            { kind: "replace", messages: [userMsg("first")], system: null },
            bad as never,
          ),
        ).rejects.toThrow();
      }

      // Nothing landed: no context, no evidence row.
      expect(await store.getContext(runId)).toBeUndefined();
      expect(await store.getEvidence(runId)).toBeUndefined();
    });
  });
});

describe("write failures roll back atomically", () => {
  it("a trigger-injected write failure leaves the old context and revision", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_trigger";
    let attemptId: string;
    await withStore(dbPath, async (store) => {
      attemptId = await admitRunning(store, runId);
      await store.commitContext(runId, attemptId, 0, {
        kind: "replace",
        messages: [userMsg("first")],
        system: "system prompt",
      });
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_ctx_insert BEFORE INSERT ON run_context " +
        "BEGIN SELECT RAISE(ABORT, 'injected context insert failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(
        store.commitContext(runId, attemptId!, 1, {
          kind: "append",
          messages: [userMsg("blocked")],
        }),
      ).rejects.toThrow();

      const context = await store.getContext(runId);
      expect(context?.revision).toBe(1);
      expect(context?.messages).toEqual([userMsg("first")]);
      expect(context?.system).toBe("system prompt");
    });
  });
});

describe("v1 databases migrate transactionally", () => {
  it("migrates a genuine B1 database, retaining run identity and admitting fresh context", async () => {
    // Build a real admitted record first, then move it into a database whose
    // schema is exactly B1's: runs table only, user_version 1.
    const runId = "run_ctx_migrate";
    const sourceDb = tempDb();
    let recordJson: string;
    let attemptId: string;
    let sessionId: string;
    await withStore(sourceDb, async (store) => {
      const admitted = await store.admit(spec(runId));
      attemptId = admitted.record.attemptId;
      sessionId = admitted.record.sessionId;
    });
    const rawSource = rawDb(sourceDb);
    recordJson = (
      rawSource
        .prepare("SELECT record_json FROM runs WHERE run_id = ?")
        .get(runId) as { record_json: string }
    ).record_json;
    rawSource.close();

    const dbPath = await b1Database(recordJson, runId);

    await withStore(dbPath, async (store) => {
      // Identity survives the migration untouched.
      const record = await store.get(runId);
      expect(record?.attemptId).toBe(attemptId);
      expect(record?.sessionId).toBe(sessionId);
      expect(record?.status).toBe("admitted");

      // B1 had no context rows; migration must not invent any.
      expect(await store.getContext(runId)).toBeUndefined();

      // Post-migration commits work: the run reaches running and a fresh
      // context ladder starts at epoch 1 revision 1 (behavioral proof the
      // v2 objects exist — a failed migration would reject here).
      await store.transition(runId, attemptId!, "running");
      const first = await store.commitContext(runId, attemptId!, 0, {
        kind: "replace",
        messages: [userMsg("first after migration")],
        system: "system prompt",
      });
      expect(first).toEqual({ epoch: 1, revision: 1 });
    });

    // Migration persists: a second open sees the migrated schema and data.
    await withStore(dbPath, async (store) => {
      const context = await store.getContext(runId);
      expect(context?.epoch).toBe(1);
      expect(context?.revision).toBe(1);
      expect(context?.messages).toEqual([userMsg("first after migration")]);
    });
  });
});

// Real subprocess crash: a bun child commits a context, signals, then idles;
// SIGKILL after the marker; the reopened store must show the committed
// context exactly, with no phantom later revision.
describe("subprocess crash persistence", () => {
  it("preserves the exact committed context after SIGKILL", async () => {
    const dbPath = tempDb();
    const runId = "run_ctx_crash";
    const cwd = tempDir("runcontext-cwd-");

    const fixtureDir = tempDir("runcontext-fixture-");
    const script = join(fixtureDir, "committer.ts");
    const storeSource = join(import.meta.dirname, "sqliteRunStore.ts");
    writeFileSync(
      script,
      `
import { openSqliteRunStore } from ${JSON.stringify(storeSource)};

const [dbPath, runId] = process.argv.slice(2);
const store = await openSqliteRunStore(dbPath);
const admitted = await store.admit({
  schemaVersion: 1,
  configVersion: 1,
  runId,
  prompt: "Request the target homepage once and summarize the response.",
  target: "http://127.0.0.1:8080",
  model: "claude-sonnet-5-5",
  activeTools: ["http_request"],
  environment: { kind: "local", cwd: ${JSON.stringify(cwd)} },
  scope: {
    version: 1,
    allowedHosts: ["127.0.0.1"],
    allowedPorts: [8080],
    strictScope: true,
    allowDestructiveActions: false,
    allowRateLimitTesting: false,
  },
  credentialRefs: [],
});
await store.transition(runId, admitted.record.attemptId, "running");
const committed = await store.commitContext(runId, admitted.record.attemptId, 0, {
  kind: "replace",
  messages: [{ role: "user", content: "committed before crash" }],
  system: "system prompt",
});
console.log(JSON.stringify({
  attemptId: admitted.record.attemptId,
  epoch: committed.epoch,
  revision: committed.revision,
}));
setInterval(() => {}, 1000);
`,
    );

    holdChild = spawn("bun", [script, dbPath, runId], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    holdChild.stdout!.on("data", (chunk) => (stdout += chunk));
    const marker = await new Promise<{
      attemptId: string;
      epoch: number;
      revision: number;
    }>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`committer produced no marker: ${stdout}`)),
        20000,
      );
      holdChild!.stdout!.on("data", () => {
        const line = stdout.trim().split("\n").pop();
        if (!line) return;
        try {
          clearTimeout(timer);
          resolve(JSON.parse(line));
        } catch {
          // wait for the full JSON line
        }
      });
      holdChild!.on("error", reject);
    });
    expect(marker.epoch).toBe(1);
    expect(marker.revision).toBe(1);

    holdChild.kill("SIGKILL");
    await new Promise<void>((resolve) =>
      holdChild!.on("close", () => resolve()),
    );

    await withStore(dbPath, async (store) => {
      expect((await store.get(runId))?.status).toBe("running");
      const context = await store.getContext(runId);
      expect(context?.epoch).toBe(1);
      expect(context?.revision).toBe(1);
      expect(context?.system).toBe("system prompt");
      expect(context?.messages).toEqual([
        { role: "user", content: "committed before crash" },
      ]);
    });
  });
});
