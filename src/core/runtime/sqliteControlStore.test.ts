import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  RunControlConflictError,
  RunControlInterruption,
} from "./runControlStore";
import type { RecordedRunSpec, RunRecord } from "./runStore";
import {
  CONTROL_STORE_SCHEMA_SQL,
  createSqliteControlStore,
} from "./sqliteControlStore";
import { openSqliteRunStore } from "./sqliteRunStore";

// Control-store tests construct the helper directly over the real SQLite
// database — green before and after root wires the v5 migration, because the
// helper contract is exactly what the wiring will call.

type RunStore = Awaited<ReturnType<typeof openSqliteRunStore>>;
type Control = ReturnType<typeof createSqliteControlStore>;

let tempDirs: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("controlstore-db-"), "runs.sqlite");
}

const cwdByRunId = new Map<string, string>();

type SpecTool = RecordedRunSpec["activeTools"][number];

function spec(runId: string, requiredTools: SpecTool[] = []): RecordedRunSpec {
  let cwd = cwdByRunId.get(runId);
  if (!cwd) {
    cwd = tempDir("controlstore-cwd-");
    cwdByRunId.set(runId, cwd);
  }
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId,
    prompt: "Request the target homepage once and summarize the response.",
    target: "http://127.0.0.1:8080",
    model: "claude-sonnet-5-5",
    activeTools: ["http_request", "execute_command"],
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
    ...(requiredTools.length ? { approval: { requiredTools } } : {}),
  };
}

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

function rawTransaction(db: RawConnection) {
  return <T>(operation: () => T): T => {
    db.exec("BEGIN IMMEDIATE");
    try {
      const value = operation();
      db.exec("COMMIT");
      return value;
    } catch (error) {
      try {
        db.exec("ROLLBACK");
      } catch {
        // The operation's error is the one to surface.
      }
      throw error;
    }
  };
}

/** The helper wired exactly as root's store integration will wire it. */
async function withControl<T>(
  dbPath: string,
  fn: (store: RunStore, control: Control, dbPath: string) => Promise<T>,
): Promise<T> {
  const store = await openSqliteRunStore(dbPath);
  const db = rawDb(dbPath);
  try {
    const hasControls = db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'run_controls'",
      )
      .get();
    if (!hasControls) db.exec(CONTROL_STORE_SCHEMA_SQL);
    // The adapter reads the stored record loosely so the fault-injection
    // tests can patch spec fields the schema would re-normalize.
    const control = createSqliteControlStore({
      db,
      transaction: rawTransaction(db),
      getRun: (runId) => {
        const row = db
          .prepare("SELECT record_json FROM runs WHERE run_id = ?")
          .get(runId);
        if (row == null) return undefined;
        const record = JSON.parse(
          (row as { record_json: string }).record_json,
        ) as RunRecord & { spec: { approval?: { requiredTools: string[] } } };
        if (record.spec.runId !== runId) {
          throw new Error("Run identity mismatch");
        }
        return record;
      },
      getContextReference: (runId) => {
        const head = db
          .prepare(
            "SELECT epoch, revision FROM run_context WHERE run_id = ? ORDER BY revision DESC LIMIT 1",
          )
          .get(runId) as { epoch: number; revision: number } | null | undefined;
        return head ? { epoch: head.epoch, revision: head.revision } : null;
      },
    });
    return await fn(store, control, dbPath);
  } finally {
    db.close();
    store.close();
  }
}

async function setupRun(
  store: RunStore,
  dbPath: string,
  runId: string,
  requiredTools: SpecTool[] = [],
): Promise<string> {
  const admitted = await store.admit(spec(runId, requiredTools));
  await store.transition(runId, admitted.record.attemptId, "running");
  await store.commitContext(runId, admitted.record.attemptId, 0, {
    kind: "replace",
    messages: [{ role: "user", content: "first" }],
    system: null,
  });
  return admitted.record.attemptId;
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("control enrollment", () => {
  it("enrolls at admitted or running; never terminal; idempotent per owner", async () => {
    await withControl(tempDb(), async (store, control) => {
      const runId = "run_ctl_enroll";
      const admitted = await store.admit(spec(runId));

      // Root initializes immediately after admission.
      await control.methods.initializeControl(runId, admitted.record.attemptId);
      await control.methods.initializeControl(runId, admitted.record.attemptId);
      expect(control.readControl(runId)).toMatchObject({
        intent: "run",
        revision: 0,
      });

      await store.transition(runId, admitted.record.attemptId, "running");
      await control.methods.initializeControl(runId, admitted.record.attemptId);

      await store.transition(runId, admitted.record.attemptId, "completed");
      await expect(
        control.methods.initializeControl(runId, admitted.record.attemptId),
      ).rejects.toThrow(/not enrollable/);

      await expect(
        control.methods.initializeControl(
          runId,
          "exec_00000000-0000-4000-8000-000000000001",
        ),
      ).rejects.toThrow(/does not own this run/);
    });
  });

  it("sync readControl reports undefined for unenrolled runs and matches getControl", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_read";
      const exec = await setupRun(store, dbPath, runId);
      expect(control.readControl(runId)).toBeUndefined();

      await control.methods.initializeControl(runId, exec);
      expect(control.readControl(runId)).toEqual(
        await control.methods.getControl(runId),
      );
    });
  });

  it("reports corrupt control rows explicitly", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_corrupt";
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId);
      await control.methods.initializeControl(runId, exec);
    });

    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE run_controls SET record_json = ? WHERE run_id = ?")
      .run("{not json", runId);
    raw.close();

    await withControl(dbPath, async (_store, control) => {
      await expect(control.methods.getControl(runId)).rejects.toThrow();
      expect(() => control.readControl(runId)).toThrow();
      await expect(
        control.methods.requestControl(runId, "pause", 0),
      ).rejects.toThrow();
    });
  });
});

describe("control commands", () => {
  it("pauses and stops with revision CAS; identical intent idempotent", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_cas";
      const exec = await setupRun(store, dbPath, runId);
      await control.methods.initializeControl(runId, exec);

      const paused = await control.methods.requestControl(runId, "pause", 0);
      expect(paused).toMatchObject({ intent: "pause", revision: 1 });

      await expect(
        control.methods.requestControl(runId, "stop", 0),
      ).rejects.toThrow(RunControlConflictError);
      const again = await control.methods.requestControl(runId, "pause", 1);
      expect(again.revision).toBe(1);

      const stopped = await control.methods.requestControl(runId, "stop", 1);
      expect(stopped).toMatchObject({ intent: "stop", revision: 2 });

      await expect(
        control.methods.requestControl(runId, "pause", 2),
      ).rejects.toThrow(/Stop dominates/);
    });
  });

  it("rejects commands against unenrolled runs without fabricating history", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_unenrolled";
      await setupRun(store, dbPath, runId);
      await expect(
        control.methods.requestControl(runId, "pause", 0),
      ).rejects.toThrow(/not initialized/);
      expect(await control.methods.getControl(runId)).toBeUndefined();
    });
  });

  it("persists stop on an admitted run before it becomes cancelled", async () => {
    await withControl(tempDb(), async (store, control) => {
      const runId = "run_ctl_preabort";
      const admitted = await store.admit(spec(runId));

      await control.methods.initializeControl(runId, admitted.record.attemptId);
      const stopped = await control.methods.requestControl(runId, "stop", 0);
      expect(stopped.intent).toBe("stop");

      await store.transition(runId, admitted.record.attemptId, "cancelled");
      expect((await control.methods.getControl(runId))?.intent).toBe("stop");
    });
  });

  it("stop denies pending approvals in the same transaction", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_stop_deny";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      expect(approval.state).toBe("pending");

      await control.methods.requestControl(runId, "stop", 0);

      const denied = await control.methods.getApproval(
        runId,
        approval.approvalId,
      );
      expect(denied).toMatchObject({ state: "denied", reason: "run_stopped" });
    });
  });
});

describe("approval requests", () => {
  it("binds input, spec digest, and context; dedups identical; conflicts reject", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_approval";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);

      const request = {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      };
      const first = await control.methods.requestApproval(runId, exec, request);
      expect(first.state).toBe("pending");
      expect(first.context).toEqual({ epoch: 1, revision: 1 });
      expect(first.specDigest).toMatch(/^[a-f0-9]{64}$/);

      const again = await control.methods.requestApproval(runId, exec, request);
      expect(again.approvalId).toBe(first.approvalId);

      await expect(
        control.methods.requestApproval(runId, exec, {
          ...request,
          input: { url: "http://other/" },
        }),
      ).rejects.toThrow(/different tool identity or input/);
      await expect(
        control.methods.requestApproval(runId, exec, {
          ...request,
          toolName: "execute_command",
        }),
      ).rejects.toThrow(/different tool identity or input/);
      expect(await control.methods.listApprovals(runId)).toHaveLength(1);
    });
  });

  it("requires enrollment, running owner, allowlisted tools, and JSON input", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_approval_gates";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);

      await expect(
        control.methods.requestApproval(runId, exec, {
          toolCallId: "tc_1",
          toolName: "http_request",
          input: {},
        }),
      ).rejects.toThrow(/not initialized/);

      await control.methods.initializeControl(runId, exec);

      await expect(
        control.methods.requestApproval(runId, exec, {
          toolCallId: "tc_1",
          toolName: "document_vulnerability",
          input: {},
        }),
      ).rejects.toThrow(/active tool allowlist/);

      const circular: Record<string, unknown> = { url: "http://x/" };
      circular.self = circular;
      await expect(
        control.methods.requestApproval(runId, exec, {
          toolCallId: "tc_1",
          toolName: "http_request",
          input: circular,
        }),
      ).rejects.toThrow();

      expect(await control.methods.listApprovals(runId)).toEqual([]);
    });
  });
});

describe("approval resolution", () => {
  it("resolves once; identical idempotent; conflicting rejects; deny records user_rejected", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_resolve";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });

      const approved = await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "approved",
      );
      expect(approved.state).toBe("approved");

      const again = await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "approved",
      );
      expect(again.decidedAt).toBe(approved.decidedAt);

      await expect(
        control.methods.resolveApproval(runId, approval.approvalId, "denied"),
      ).rejects.toThrow(/different decision/);

      const second = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_2",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/admin" },
      });
      const denied = await control.methods.resolveApproval(
        runId,
        second.approvalId,
        "denied",
      );
      expect(denied).toMatchObject({
        state: "denied",
        reason: "user_rejected",
      });

      await expect(
        control.methods.resolveApproval(runId, second.approvalId, "approved"),
      ).rejects.toThrow(/different decision/);
    });
  });

  it("cannot approve a stopped or terminal run", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_resolve_terminal";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      await store.transition(runId, exec, "completed");

      await expect(
        control.methods.resolveApproval(runId, approval.approvalId, "approved"),
      ).rejects.toThrow(/cannot approve/);
      const denied = await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "denied",
      );
      expect(denied.state).toBe("denied");
    });
  });

  it("persists pending decisions across reopen", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_reopen";
    let approvalId: string;
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      approvalId = approval.approvalId;
      await control.methods.requestControl(runId, "pause", 0);
    });

    await withControl(dbPath, async (_store, control) => {
      const controlRecord = await control.methods.getControl(runId);
      expect(controlRecord).toMatchObject({ intent: "pause", revision: 1 });
      const approval = await control.methods.getApproval(runId, approvalId!);
      expect(approval?.state).toBe("pending");

      const approved = await control.methods.resolveApproval(
        runId,
        approvalId!,
        "approved",
      );
      expect(approved.state).toBe("approved");
    });
  });
});

describe("synchronous dispatch gates", () => {
  it("allows dispatch with no enrollment or run intent; blocks pause and stop", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_gates";
      const exec = await setupRun(store, dbPath, runId);

      control.assertDispatchAllowed(runId);

      await control.methods.initializeControl(runId, exec);
      control.assertDispatchAllowed(runId);

      await control.methods.requestControl(runId, "pause", 0);
      expect(() => control.assertDispatchAllowed(runId)).toThrowError(
        RunControlInterruption,
      );

      await control.methods.requestControl(runId, "stop", 1);
      expect(() => control.assertDispatchAllowed(runId)).toThrowError(
        RunControlInterruption,
      );
    });
  });

  it("refuses absent enrollment for specs requiring approvals; ungated legacy stays compatible", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const gated = "run_ctl_gated_unenrolled";
      await setupRun(store, dbPath, gated, ["http_request"]);
      expect(() => control.assertDispatchAllowed(gated)).toThrow(
        /Control is not initialized/,
      );

      const legacy = "run_ctl_legacy_unenrolled";
      await setupRun(store, dbPath, legacy);
      control.assertDispatchAllowed(legacy);
    });
  });

  it("rejects a control record enrolled by another execution attempt", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_owner_mismatch";
    let exec: string;
    await withControl(dbPath, async (store, control, dbPath) => {
      exec = await setupRun(store, dbPath, runId);
      await control.methods.initializeControl(runId, exec);
    });

    const raw = rawDb(dbPath);
    raw.prepare("UPDATE run_controls SET record_json = ? WHERE run_id = ?").run(
      JSON.stringify({
        schemaVersion: 1,
        runId,
        executionAttemptId: "exec_00000000-0000-4000-8000-0000000000ff",
        intent: "run",
        revision: 0,
        updatedAt: new Date().toISOString(),
      }),
      runId,
    );
    raw.close();

    await withControl(dbPath, async (_store, control) => {
      expect(() => control.assertDispatchAllowed(runId)).toThrow(
        /enrolled by another execution attempt/,
      );
    });
  });

  it("requires an approved, matching approval for gated tool calls only", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_tool_gate";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      const input = { url: "http://127.0.0.1:8080/" };

      // Even an ungated tool cannot dispatch while unenrolled on a gated spec.
      expect(() =>
        control.assertToolApproved(runId, "execute_command", "tc_x", input),
      ).toThrow(/Control is not initialized/);

      await control.methods.initializeControl(runId, exec);

      // Ungated tool passes with no approval record.
      control.assertToolApproved(runId, "execute_command", "tc_x", input);

      // Not admitted to the run at all.
      expect(() =>
        control.assertToolApproved(
          runId,
          "document_vulnerability",
          "tc_x",
          input,
        ),
      ).toThrow(/active tool allowlist/);

      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input,
      });

      // Pending does not authorize dispatch.
      expect(() =>
        control.assertToolApproved(runId, "http_request", "tc_1", input),
      ).toThrowError(RunControlInterruption);

      await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "approved",
      );

      // Wrong input and unknown tool call id reject; the exact identity passes.
      expect(() =>
        control.assertToolApproved(runId, "http_request", "tc_1", {
          url: "http://other/",
        }),
      ).toThrowError(RunControlInterruption);
      expect(() =>
        control.assertToolApproved(runId, "http_request", "tc_missing", input),
      ).toThrowError(RunControlInterruption);
      control.assertToolApproved(runId, "http_request", "tc_1", input);
    });
  });

  it("rejects an approval granted for a different gated tool", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_wrong_tool";
      const exec = await setupRun(store, dbPath, runId, [
        "http_request",
        "execute_command",
      ]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "approved",
      );

      // Both tools are gated; the approval names http_request, not this one.
      expect(() =>
        control.assertToolApproved(runId, "execute_command", "tc_1", {
          command: "ls",
        }),
      ).toThrowError(RunControlInterruption);
    });
  });

  it("always applies the dispatch check first, even for ungated tools", async () => {
    await withControl(tempDb(), async (store, control, dbPath) => {
      const runId = "run_ctl_gate_first";
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      await control.methods.requestControl(runId, "pause", 0);

      expect(() =>
        control.assertToolApproved(runId, "execute_command", "tc_x", {
          command: "ls",
        }),
      ).toThrowError(RunControlInterruption);
    });
  });

  it("blocks approval reuse after the spec digest changes", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_digest";
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "approved",
      );
    });

    const raw = rawDb(dbPath);
    const row = raw
      .prepare("SELECT record_json FROM runs WHERE run_id = ?")
      .get(runId) as { record_json: string };
    const record = JSON.parse(row.record_json);
    record.spec.prompt = "tampered prompt";
    raw
      .prepare("UPDATE runs SET record_json = ? WHERE run_id = ?")
      .run(JSON.stringify(record), runId);
    raw.close();

    await withControl(dbPath, async (_store, control) => {
      expect(() =>
        control.assertToolApproved(runId, "http_request", "tc_1", {
          url: "http://127.0.0.1:8080/",
        }),
      ).toThrowError(RunControlInterruption);
    });
  });

  it("blocks an approval granted under another execution attempt", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_attempt_mismatch";
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      await control.methods.resolveApproval(
        runId,
        approval.approvalId,
        "approved",
      );

      // Fault injection: the approval claims a different executor.
      const db = rawDb(dbPath);
      const row = db
        .prepare(
          "SELECT record_json FROM tool_approvals WHERE run_id = ? AND tool_call_id = ?",
        )
        .get(runId, "tc_1") as { record_json: string };
      const record = JSON.parse(row.record_json);
      record.executionAttemptId = "exec_00000000-0000-4000-8000-0000000000ff";
      db.prepare(
        "UPDATE tool_approvals SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
      ).run(JSON.stringify(record), runId, "tc_1");
      db.close();
    });

    await withControl(dbPath, async (_store, control) => {
      expect(() =>
        control.assertToolApproved(runId, "http_request", "tc_1", {
          url: "http://127.0.0.1:8080/",
        }),
      ).toThrowError(RunControlInterruption);
    });
  });
});

describe("corruption and transaction rollback", () => {
  it("rejects state-dependent shape violations and key mismatches on read", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_corrupt_approvals";
    const approvalIds: string[] = [];
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      for (const [id, url] of [
        ["tc_1", "http://127.0.0.1:8080/"],
        ["tc_2", "http://127.0.0.1:8080/admin"],
      ] as const) {
        const approval = await control.methods.requestApproval(runId, exec, {
          toolCallId: id,
          toolName: "http_request",
          input: { url },
        });
        approvalIds.push(approval.approvalId);
      }
      await control.methods.resolveApproval(runId, approvalIds[0]!, "denied");
    });

    const raw = rawDb(dbPath);
    const read = (toolCallId: string) =>
      (
        raw
          .prepare(
            "SELECT record_json FROM tool_approvals WHERE run_id = ? AND tool_call_id = ?",
          )
          .get(runId, toolCallId) as { record_json: string }
      ).record_json;
    const write = (toolCallId: string, json: string) =>
      raw
        .prepare(
          "UPDATE tool_approvals SET record_json = ? WHERE run_id = ? AND tool_call_id = ?",
        )
        .run(json, runId, toolCallId);

    // Denied record stripped of decidedAt.
    const denied = JSON.parse(read("tc_1"));
    write("tc_1", JSON.stringify({ ...denied, decidedAt: undefined }));
    // Pending record carrying a reason and decidedAt.
    const pending = JSON.parse(read("tc_2"));
    write(
      "tc_2",
      JSON.stringify({
        ...pending,
        reason: "run_stopped",
        decidedAt: denied.updatedAt ?? new Date().toISOString(),
      }),
    );
    // Key mismatch: tc_1's row holds tc_2's record.
    const second = read("tc_2");
    write("tc_2", read("tc_1"));
    raw.close();

    await withControl(dbPath, async (_store, control) => {
      await expect(control.methods.listApprovals(runId)).rejects.toThrow();
      await expect(
        control.methods.getApproval(runId, approvalIds[0]!),
      ).rejects.toThrow();
      await expect(
        control.methods.resolveApproval(runId, approvalIds[0]!, "approved"),
      ).rejects.toThrow();
    });
    void second;
  });

  it("rolls a stop command back when the control write fails", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_stop_rollback";
    let approvalId: string;
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      approvalId = approval.approvalId;
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_ctl_insert BEFORE INSERT ON run_controls " +
        "BEGIN SELECT RAISE(ABORT, 'injected control write failure'); END",
    );
    raw.exec(
      "CREATE TRIGGER reject_ctl_update BEFORE UPDATE ON run_controls " +
        "BEGIN SELECT RAISE(ABORT, 'injected control write failure'); END",
    );
    raw.close();

    await withControl(dbPath, async (_store, control) => {
      await expect(
        control.methods.requestControl(runId, "stop", 0),
      ).rejects.toThrow();
      expect(control.readControl(runId)).toMatchObject({
        intent: "run",
        revision: 0,
      });
      // The stop's approval denial rolled back with it.
      expect(
        (await control.methods.getApproval(runId, approvalId!))?.state,
      ).toBe("pending");
    });
  });

  it("rolls approval resolution back when the approval write fails", async () => {
    const dbPath = tempDb();
    const runId = "run_ctl_resolve_rollback";
    let approvalId: string;
    await withControl(dbPath, async (store, control, dbPath) => {
      const exec = await setupRun(store, dbPath, runId, ["http_request"]);
      await control.methods.initializeControl(runId, exec);
      const approval = await control.methods.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
      approvalId = approval.approvalId;
    });

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_approval_update BEFORE UPDATE ON tool_approvals " +
        "BEGIN SELECT RAISE(ABORT, 'injected approval write failure'); END",
    );
    raw.close();

    await withControl(dbPath, async (_store, control) => {
      await expect(
        control.methods.resolveApproval(runId, approvalId!, "approved"),
      ).rejects.toThrow();
      expect(
        (await control.methods.getApproval(runId, approvalId!))?.state,
      ).toBe("pending");
    });
  });
});

it("rejects an approval request racing a persisted stop and rejects invalid decisions without changing pending state", async () => {
  await withControl(tempDb(), async (store, control, dbPath) => {
    const runId = "run_approval_stop_race";
    const exec = await setupRun(store, dbPath, runId, ["http_request"]);
    await store.initializeControl(runId, exec);
    const request = {
      toolCallId: "call_1",
      toolName: "http_request",
      input: { url: "http://127.0.0.1:8080/" },
    };
    const pending = await store.requestApproval(runId, exec, request);
    await expect(
      store.resolveApproval(runId, pending.approvalId, "invalid" as never),
    ).rejects.toThrow();
    expect((await store.getApproval(runId, pending.approvalId))?.state).toBe(
      "pending",
    );
    await store.requestControl(runId, "stop", 0);
    await expect(
      store.requestApproval(runId, exec, { ...request, toolCallId: "call_2" }),
    ).rejects.toBeInstanceOf(RunControlInterruption);
    expect(await control.methods.listApprovals(runId)).toHaveLength(1);
    expect((await store.getApproval(runId, pending.approvalId))?.state).toBe(
      "denied",
    );
  });
});
