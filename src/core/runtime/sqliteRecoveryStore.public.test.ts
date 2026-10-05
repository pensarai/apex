import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startInferenceAttempt } from "../ai/inference-attempt";
import { acquireLocalRunLock } from "./localRunLock";
import type { RecordedRunSpec } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

// Enrolled execution writes through the PUBLIC store: every mutation below
// must refuse while the execution lock is not held; client-side control
// commands stay lock-free.

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

let tempDirs: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function spec(runId: string, cwd: string): RecordedRunSpec {
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

/** Fully set-up enrolled running run, lock NOT held; returns (exec, modelHandle). */
async function enrolledUnlockedRun(
  store: Store,
  runId: string,
  sessionRoot: string,
): Promise<{ exec: string }> {
  const admitted = await store.admit(spec(runId, tempDir("pubgate-cwd-")));
  const exec = admitted.record.attemptId;
  const lock = await store.acquireExecutionLock(runId);
  try {
    await store.enrollRecovery(runId, exec, sessionRoot);
    await store.transition(runId, exec, "running");
    await store.initializeToolJournal(runId, exec);
    await store.initializeControl(runId, exec);
    await store.commitContext(runId, exec, 0, {
      kind: "replace",
      messages: [{ role: "user", content: "first" }],
      system: null,
    });
  } finally {
    lock.release();
  }
  return { exec };
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("public store gates enrolled execution writes on the lock", () => {
  it("rejects stale owners after a claim even when the caller holds the lock", async () => {
    const store = await openSqliteRunStore(
      join(tempDir("pubgate-db-"), "runs.sqlite"),
    );
    const runId = "run_stale_owner";
    try {
      const { exec } = await enrolledUnlockedRun(
        store,
        runId,
        tempDir("pubgate-session-"),
      );
      const lock = await store.acquireExecutionLock(runId);
      try {
        const recovery = await store.claimRecovery(runId, {
          expectedAttemptId: exec,
          expectedContext: { epoch: 1, revision: 1 },
          expectedControlRevision: 0,
          reconstruction: {
            sourceContext: { epoch: 1, revision: 1 },
            reconstructedToolCalls: [],
            deniedToolCalls: [],
            restartedModelAttempts: [],
            discardedUncommitted: false,
          },
        });
        await expect(
          store.commitContext(runId, exec, 1, {
            kind: "append",
            messages: [{ role: "user", content: "stale" }],
          }),
        ).rejects.toThrow(/does not own/);
        await expect(
          store.transition(runId, exec, "completed"),
        ).rejects.toThrow(/does not own/);
        const model = startInferenceAttempt({
          operationKind: "agent.stream",
          requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
        });
        await expect(
          store.startModelAttempt(runId, exec, model.started),
        ).rejects.toThrow(/does not own/);
        await store.commitContext(runId, recovery.toAttemptId, 1, {
          kind: "append",
          messages: [{ role: "user", content: "current" }],
        });
        expect((await store.getContext(runId))?.revision).toBe(2);
      } finally {
        lock.release();
      }
    } finally {
      store.close();
    }
  });

  it("refuses every execution mutation from a reopened (unlocked) client", async () => {
    const dbPath = join(tempDir("pubgate-db-"), "runs.sqlite");
    const runId = "run_pub_gate";
    const sessionRoot = tempDir("pubgate-session-");
    let exec: string;
    {
      const store = await openSqliteRunStore(dbPath);
      try {
        exec = (await enrolledUnlockedRun(store, runId, sessionRoot)).exec;
      } finally {
        store.close();
      }
    }

    const store = await openSqliteRunStore(dbPath);
    try {
      const handle = startInferenceAttempt({
        operationKind: "agent.stream",
        requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
      });
      const started = handle.started;
      const approvalInput = { url: "http://127.0.0.1:8080/" };

      const gated: Array<[string, Promise<unknown>]> = [
        ["transition", store.transition(runId, exec, "running")],
        [
          "commitContext",
          store.commitContext(runId, exec, 1, {
            kind: "append",
            messages: [{ role: "assistant", content: "second" }],
          }),
        ],
        ["initializeToolJournal", store.initializeToolJournal(runId, exec)],
        ["initializeControl", store.initializeControl(runId, exec)],
        ["startModelAttempt", store.startModelAttempt(runId, exec, started)],
        [
          "recordRetry",
          store.recordRetry(runId, exec, {
            authority: "stream-rate-limit",
            count: 1,
            maxRetries: 20,
            delayMs: 100,
          }),
        ],
        [
          "startToolOperation",
          store.startToolOperation(runId, exec, {
            toolCallId: "tc_1",
            toolName: "http_request",
            input: approvalInput,
            policy: "external_effect",
          }),
        ],
        [
          "markToolOutcomeUnknown",
          store.markToolOutcomeUnknown(runId, exec, "tc_1"),
        ],
      ];
      for (const [name, call] of gated) {
        await expect(call, `${name} must require the lock`).rejects.toThrow(
          /Execution lock is not held/,
        );
      }
      // requestApproval is executor-side and gates on the lock too.
      await expect(
        store.requestApproval(runId, exec, {
          toolCallId: "tc_approval",
          toolName: "http_request",
          input: approvalInput,
        }),
        "requestApproval must require the lock",
      ).rejects.toThrow(/Execution lock is not held/);

      // Reads stay available.
      expect((await store.get(runId))?.attemptId).toBe(exec);
      expect(await store.getContext(runId)).toBeDefined();
      expect((await store.getControl(runId))?.intent).toBe("run");

      // Client control commands remain lock-free: requestControl and
      // resolveApproval (no pending approval exists here; the resolve
      // error would be "does not exist", never the lock error).
      const paused = await store.requestControl(runId, "pause", 0);
      expect(paused.intent).toBe("pause");
      const resumed = await store.requestControl(runId, "pause", 1);
      expect(resumed.intent).toBe("pause");
      await store.requestControl(runId, "stop", resumed.revision);
      const stoppedControl = await store.getControl(runId);
      expect(stoppedControl?.intent).toBe("stop");
    } finally {
      store.close();
    }
  });

  it("executor-side approval request and model/tool writes pass under the held lock", async () => {
    const dbPath = join(tempDir("pubgate-db-"), "runs.sqlite");
    const runId = "run_pub_locked";
    const store = await openSqliteRunStore(dbPath);
    try {
      const sessionRoot = tempDir("pubgate-session-");
      const { exec } = await enrolledUnlockedRun(store, runId, sessionRoot);
      const lock = await store.acquireExecutionLock(runId);
      try {
        const approval = await store.requestApproval(runId, exec, {
          toolCallId: "tc_1",
          toolName: "http_request",
          input: { url: "http://127.0.0.1:8080/" },
        });
        expect(approval.state).toBe("pending");
        const approved = await store.resolveApproval(
          runId,
          approval.approvalId,
          "approved",
        );
        expect(approved.state).toBe("approved");

        const handle = startInferenceAttempt({
          operationKind: "agent.stream",
          requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
        });
        await store.startModelAttempt(runId, exec, handle.started);
        await store.observeModelToolCall(runId, exec, handle.attemptId, {
          toolCallId: "tc_1",
          toolName: "http_request",
        });
        await store.settleModelAttempt(runId, exec, handle.complete());

        const started = await store.startToolOperation(runId, exec, {
          toolCallId: "tc_1",
          toolName: "http_request",
          input: { url: "http://127.0.0.1:8080/" },
          policy: "external_effect",
        });
        expect(started.created).toBe(true);
        await store.settleToolOperation(
          runId,
          exec,
          "tc_1",
          { type: "text", value: "done" },
          { rootPath: sessionRoot, files: [] },
        );
        await store.recordRetry(runId, exec, {
          authority: "stream-idle",
          count: 1,
          maxRetries: 3,
          delayMs: 0,
        });
        expect((await store.listModelAttempts(runId)).length).toBe(1);
      } finally {
        lock.release();
      }

      // Same store, lock released: mutations refuse again.
      const handle2 = startInferenceAttempt({
        operationKind: "agent.stream",
        requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
      });
      await expect(
        store.startModelAttempt(runId, exec, handle2.started),
      ).rejects.toThrow(/Execution lock is not held/);
    } finally {
      store.close();
    }
  });

  it("same-process double acquire through the public store refuses", async () => {
    const dbPath = join(tempDir("pubgate-db-"), "runs.sqlite");
    const store = await openSqliteRunStore(dbPath);
    try {
      const runId = "run_pub_double";
      const admitted = await store.admit(spec(runId, tempDir("pubgate-cwd-")));
      const lock = await store.acquireExecutionLock(runId);
      await expect(store.acquireExecutionLock(runId)).rejects.toThrow(
        /already held/,
      );
      // The underlying OS lock also refuses a direct second holder.
      await expect(acquireLocalRunLock(runId, dbPath)).rejects.toThrow(
        /held by another executor/,
      );
      lock.release();
      const again = await store.acquireExecutionLock(runId);
      again.release();
      expect(admitted.created).toBe(true);
    } finally {
      store.close();
    }
  });

  it("symlink-aliased database paths address the same lock file", async () => {
    const dir = tempDir("pubgate-symlink-");
    const realDir = join(dir, "real");
    const realDb = join(realDir, "runs.sqlite");
    const store = await openSqliteRunStore(realDb);
    try {
      const runId = "run_pub_symlink";
      await store.admit(spec(runId, tempDir("pubgate-cwd-")));
      const lock = await store.acquireExecutionLock(runId);

      // An alias directory pointing at the real one.
      const aliasDir = join(dir, "alias");
      symlinkSync(realDir, aliasDir);
      const aliasDb = join(aliasDir, "runs.sqlite");

      await expect(acquireLocalRunLock(runId, aliasDb)).rejects.toThrow(
        /held by another executor/,
      );
      // The public store opened through the alias sees the same OS lock.
      const aliasStore = await openSqliteRunStore(aliasDb);
      try {
        await expect(aliasStore.acquireExecutionLock(runId)).rejects.toThrow(
          /held by another executor|already held/,
        );
      } finally {
        aliasStore.close();
      }
      lock.release();
    } finally {
      store.close();
    }
  });
});
