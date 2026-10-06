import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openSqliteRunStore } from "./sqliteRunStore";

// Observation tests: atomic lock-free snapshots through the public store.

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

let tempDirs: string[] = [];
const holdChildren: Array<ReturnType<typeof spawn>> = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("observation-db-"), "runs.sqlite");
}

function spec(runId: string, cwd: string) {
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

const requireModule = createRequire(import.meta.url);

interface RawConnection {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...values: unknown[]): unknown;
    get(...values: unknown[]): unknown;
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

/** Fully populated enrolled running run with lock released at the end. */
async function populatedRun(dbPath: string, runId: string): Promise<void> {
  const store = await openSqliteRunStore(dbPath);
  try {
    const cwd = tempDir("observation-cwd-");
    const sessionRoot = tempDir("observation-session-");
    const admitted = await store.admit(spec(runId, cwd) as never);
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
        system: "system prompt",
      });
      await store.requestApproval(runId, exec, {
        toolCallId: "tc_1",
        toolName: "http_request",
        input: { url: "http://127.0.0.1:8080/" },
      });
    } finally {
      lock.release();
    }
  } finally {
    store.close();
  }
}

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  for (const child of holdChildren) {
    if (child.exitCode === null) child.kill("SIGKILL");
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("observe snapshots", () => {
  it("returns the full consistent observation for a populated run", async () => {
    const dbPath = tempDb();
    await populatedRun(dbPath, "run_obs_full");

    const store = await openSqliteRunStore(dbPath);
    try {
      const observation = await store.observe("run_obs_full");
      expect(observation.record?.spec.runId).toBe("run_obs_full");
      expect(observation.record?.status).toBe("running");
      expect(observation.context).toMatchObject({
        epoch: 1,
        revision: 1,
        system: "system prompt",
      });
      expect(observation.context?.messages).toEqual([
        { role: "user", content: "first" },
      ]);
      expect(observation.control).toMatchObject({
        intent: "run",
        revision: 0,
      });
      expect(observation.approvals).toHaveLength(1);
      expect(observation.approvals[0]).toMatchObject({
        state: "pending",
        toolCallId: "tc_1",
      });
    } finally {
      store.close();
    }
  });

  it("returns nulls for a missing run without touching other runs", async () => {
    const dbPath = tempDb();
    await populatedRun(dbPath, "run_obs_present");

    const store = await openSqliteRunStore(dbPath);
    try {
      const missing = await store.observe("run_obs_missing");
      expect(missing).toEqual({
        record: null,
        context: null,
        control: null,
        approvals: [],
      });
      const present = await store.observe("run_obs_present");
      expect(present.record).not.toBeNull();
      expect(present.approvals).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  it("reads without the execution lock while an executor holds it", async () => {
    const dbPath = tempDb();
    const runId = "run_obs_locked";
    const store = await openSqliteRunStore(dbPath);
    try {
      const cwd = tempDir("observation-cwd-");
      const sessionRoot = tempDir("observation-session-");
      const admitted = await store.admit(spec(runId, cwd) as never);
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

        // Client observation while the executor lock is held by this store.
        const observation = await store.observe(runId);
        expect(observation.record?.status).toBe("running");
        expect(observation.context?.revision).toBe(1);
        expect(observation.control?.intent).toBe("run");
      } finally {
        lock.release();
      }

      // A second store instance (a detached client) observes lock-free too.
      const client = await openSqliteRunStore(dbPath);
      try {
        const observation = await client.observe(runId);
        expect(observation.record?.attemptId).toBe(exec);
      } finally {
        client.close();
      }
    } finally {
      store.close();
    }
  });

  it("surfaces corruption instead of silently nulling it", async () => {
    const dbPath = tempDb();
    await populatedRun(dbPath, "run_obs_corrupt");

    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE run_controls SET record_json = ? WHERE run_id = ?")
      .run("{not json", "run_obs_corrupt");
    raw.close();

    const store = await openSqliteRunStore(dbPath);
    try {
      await expect(store.observe("run_obs_corrupt")).rejects.toThrow();
    } finally {
      store.close();
    }
  });

  it("surfaces corrupt context rows explicitly", async () => {
    const dbPath = tempDb();
    await populatedRun(dbPath, "run_obs_ctx_corrupt");

    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE run_context SET change_json = ? WHERE run_id = ?")
      .run("{not json", "run_obs_ctx_corrupt");
    raw.close();

    const store = await openSqliteRunStore(dbPath);
    try {
      await expect(store.observe("run_obs_ctx_corrupt")).rejects.toThrow(
        /corrupt/,
      );
    } finally {
      store.close();
    }
  });

  it("does not observe another connection's uncommitted writes (WAL snapshot isolation)", async () => {
    const dbPath = tempDb();
    const runId = "run_obs_isolated";
    await populatedRun(dbPath, runId);

    const store = await openSqliteRunStore(dbPath);
    try {
      const before = await store.observe(runId);
      expect(before.context?.revision).toBe(1);

      // A separate connection opens a write transaction and commits a new
      // context revision but leaves it UNCOMMITTED while we read again.
      const writer = rawDb(dbPath);
      writer.exec("BEGIN IMMEDIATE");
      writer
        .prepare(
          "INSERT INTO run_context (run_id, revision, epoch, change_json) VALUES (?, ?, ?, ?)",
        )
        .run(
          runId,
          2,
          1,
          JSON.stringify({
            kind: "append",
            messages: [{ role: "assistant", content: "second" }],
          }),
        );

      // The observation still sees the pre-write snapshot — no torn or
      // uncommitted state leaks into the atomic read.
      const during = await store.observe(runId);
      expect(during.context?.revision).toBe(1);
      expect(during.context?.messages).toEqual([
        { role: "user", content: "first" },
      ]);

      writer.exec("COMMIT");
      writer.close();

      const after = await store.observe(runId);
      expect(after.context?.revision).toBe(2);
      expect(after.context?.messages).toEqual([
        { role: "user", content: "first" },
        { role: "assistant", content: "second" },
      ]);
    } finally {
      store.close();
    }
  });

  it("observes atomically against a real simultaneous writer subprocess", async () => {
    const dbPath = tempDb();
    const runId = "run_obs_writer";
    await populatedRun(dbPath, runId);

    // The writer bumps the context revision AND the control revision in one
    // raw SQL transaction per tick. A single-table read would see torn
    // pairs; only a true multi-table snapshot keeps them matched.
    const fixtureDir = tempDir("observation-fixture-");
    const script = join(fixtureDir, "writer.ts");
    writeFileSync(
      script,
      `
import { Database } from "bun:sqlite";
const [dbPath, runId] = process.argv.slice(2);
const db = new Database(dbPath);
const control = JSON.parse(
  db.prepare("SELECT record_json FROM run_controls WHERE run_id = ?").get(runId).record_json,
);
console.log("writer-ready");
for (let contextRevision = 2; contextRevision <= 60; contextRevision++) {
  const controlNext = {
    ...control,
    revision: contextRevision - 1,
    updatedAt: new Date().toISOString(),
  };
  db.exec("BEGIN IMMEDIATE");
  db.prepare(
    "INSERT INTO run_context (run_id, revision, epoch, change_json) VALUES (?, ?, ?, ?)",
  ).run(
    runId,
    contextRevision,
    1,
    JSON.stringify({
      kind: "append",
      messages: [{ role: "assistant", content: "tick-" + contextRevision }],
    }),
  );
  db.prepare("UPDATE run_controls SET record_json = ? WHERE run_id = ?").run(
    JSON.stringify(controlNext),
    runId,
  );
  db.exec("COMMIT");
  await new Promise((resolve) => setTimeout(resolve, 5));
}
db.close();
console.log("writer-done");
`,
    );

    const child = spawn("bun", [script, dbPath, runId], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    holdChildren.push(child);

    // Completion can fire at any moment; capture it before awaiting readiness.
    const completion = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("writer subprocess timed out")),
        30000,
      );
      let done = false;
      const settle = (error?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        error ? reject(error) : resolve();
      };
      child.stdout!.on("data", (chunk: Buffer) => {
        if (chunk.toString().includes("writer-done")) settle();
      });
      child.on("error", settle);
      child.on("close", () => {
        // close without writer-done is surfaced by the final revision assert.
        settle();
      });
    });

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("writer produced no ready marker")),
        20000,
      );
      child.stdout!.on("data", (chunk: Buffer) => {
        if (chunk.toString().includes("writer-ready")) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.on("error", reject);
    });

    const observer = await openSqliteRunStore(dbPath);
    try {
      let observations = 0;
      let lastRevision = 1;
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const observation = await observer.observe(runId);
        expect(observation.record?.status).toBe("running");
        const revision = observation.context?.revision ?? 0;
        expect(revision).toBeGreaterThanOrEqual(lastRevision);
        lastRevision = revision;
        // The matched pair proves multi-table atomicity: a torn read would
        // show a context revision the control revision disagrees with.
        expect(observation.control?.revision).toBe(revision - 1);
        const messages = observation.context?.messages ?? [];
        expect(messages[0]).toEqual({ role: "user", content: "first" });
        expect(messages).toHaveLength(revision);
        observations += 1;
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
      expect(observations).toBeGreaterThan(5);
    } finally {
      observer.close();
    }

    await completion;
    const final = await openSqliteRunStore(dbPath);
    try {
      const observation = await final.observe(runId);
      // A writer that died early cannot pass silently.
      expect(observation.context?.revision).toBe(60);
      expect(observation.context?.messages).toHaveLength(60);
      expect(observation.control?.revision).toBe(59);
    } finally {
      final.close();
    }
  });
});
