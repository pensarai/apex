import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { RecordedRunSpec } from "./runStore";
import { openSqliteRunStore } from "./sqliteRunStore";

// The default store path lives under ~/.pensar — every test passes an
// explicit database inside a temp dir so nothing touches the home directory.

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

let tempDirs: string[] = [];
let holdChild: ReturnType<typeof spawn> | undefined;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function baseSpec(runId: string, cwd: string): RecordedRunSpec {
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

// A stable cwd per runId: repeated spec(runId) calls must describe the
// identical run (duplicate semantics), not mint a fresh environment.
const cwdByRunId = new Map<string, string>();

function spec(
  runId: string,
  overrides: Partial<RecordedRunSpec> = {},
): RecordedRunSpec {
  let cwd = cwdByRunId.get(runId);
  if (!cwd) {
    cwd = tempDir("runstore-cwd-");
    cwdByRunId.set(runId, cwd);
  }
  return { ...baseSpec(runId, cwd), ...overrides };
}

// Fault injection needs a second, raw connection — the only place tests
// reach past the store's public API. createRequire, not a dynamic import:
// vite-node cannot resolve the runtime-selected sqlite builtin.
const requireModule = createRequire(import.meta.url);

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

interface RawConnection {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...values: unknown[]): unknown;
    get(...values: unknown[]): unknown;
  };
  close(): void;
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

beforeAll(() => {
  tempDirs = [];
});

afterAll(() => {
  if (holdChild?.killed === false && holdChild.exitCode === null) {
    holdChild.kill("SIGKILL");
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("sqlite run store persistence", () => {
  it("persists admission and status across reopen", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const admitted = await withStore(dbPath, async (store) => {
      const result = await store.admit(spec("run_persist"));
      return store.transition(
        "run_persist",
        result.record.attemptId,
        "running",
      );
    });

    await withStore(dbPath, async (store) => {
      const record = await store.get("run_persist");
      expect(record?.status).toBe("running");
      expect(record?.attemptId).toBe(admitted.attemptId);
      expect(record?.sessionId).toBe(admitted.sessionId);
      expect(record?.admittedAt).toBe(admitted.admittedAt);

      const listed = await store.list();
      expect(listed).toHaveLength(1);
      expect(listed[0]?.spec.runId).toBe("run_persist");
    });
  });

  it("returns the original attempt and session for a matching duplicate", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      const first = await store.admit(spec("run_dup"));
      const second = await store.admit(spec("run_dup"));

      expect(second.created).toBe(false);
      expect(second.record.attemptId).toBe(first.record.attemptId);
      expect(second.record.sessionId).toBe(first.record.sessionId);
      expect((await store.list()).length).toBe(1);
    });
  });

  it("treats the same spec with reordered keys as a duplicate, not a conflict", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      const original = spec("run_order");
      await store.admit(original);
      const reordered = {
        credentialRefs: original.credentialRefs,
        scope: original.scope,
        environment: original.environment,
        activeTools: original.activeTools,
        model: original.model,
        target: original.target,
        prompt: original.prompt,
        runId: original.runId,
        configVersion: original.configVersion,
        schemaVersion: original.schemaVersion,
      };
      const again = await store.admit(reordered);
      expect(again.created).toBe(false);
    });
  });

  it("rejects a changed input reusing an existing run ID", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      await store.admit(spec("run_conflict"));
      await expect(
        store.admit(spec("run_conflict", { prompt: "Different objective" })),
      ).rejects.toThrow(/different inputs/);
    });
  });
});

describe("attempt ownership and terminal status", () => {
  it("rejects transitions from an attempt that does not own the run", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      await store.admit(spec("run_owner"));
      await expect(
        store.transition("run_owner", "exec_not_the_owner", "running"),
      ).rejects.toThrow(/does not own this run/);
      expect((await store.get("run_owner"))?.status).toBe("admitted");
    });
  });

  it("rejects transitions for a missing run", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      await expect(
        store.transition("run_missing", "exec_any", "running"),
      ).rejects.toThrow(/Run does not exist/);
    });
  });

  it("enforces the status lattice and terminal immutability", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      const a = await store.admit(spec("run_lattice"));
      const attempt = a.record.attemptId;

      await expect(
        store.transition("run_lattice", attempt, "completed"),
      ).rejects.toThrow(/Invalid run transition/);

      await store.transition("run_lattice", attempt, "running");
      await store.transition("run_lattice", attempt, "completed");

      const same = await store.transition("run_lattice", attempt, "completed");
      expect(same.status).toBe("completed");

      for (const status of ["running", "failed", "cancelled"] as const) {
        await expect(
          store.transition("run_lattice", attempt, status),
        ).rejects.toThrow(/Invalid run transition/);
      }
      // "admitted" is not a legal transition target in the store contract;
      // a plain-JS caller forcing it must still hit the lattice rejection.
      const invalid = "admitted" as Parameters<Store["transition"]>[2];
      await expect(
        store.transition("run_lattice", attempt, invalid),
      ).rejects.toThrow(/Invalid run transition/);
      expect((await store.get("run_lattice"))?.status).toBe("completed");
    });
  });

  it("allows abandoning an admitted run before it starts", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      const a = await store.admit(spec("run_abandon"));
      const record = await store.transition(
        "run_abandon",
        a.record.attemptId,
        "cancelled",
      );
      expect(record.status).toBe("cancelled");
    });
  });
});

describe("hostile or damaged databases are explicit, never overwritten", () => {
  it("refuses a database whose header was replaced by a foreign application id", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, (store) => store.admit(spec("run_header")));

    const raw = rawDb(dbPath);
    raw.exec("PRAGMA application_id = 12345");
    raw.close();

    await expect(openSqliteRunStore(dbPath)).rejects.toThrow(
      /not an Apex run store/,
    );
  });

  it("refuses a store written by a newer schema version", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, (store) => store.admit(spec("run_version")));

    const raw = rawDb(dbPath);
    raw.exec("PRAGMA user_version = 99");
    raw.close();

    await expect(openSqliteRunStore(dbPath)).rejects.toThrow(
      /Unsupported run store version: 99/,
    );
  });

  it("refuses to initialize a non-empty database with no header", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const raw = rawDb(dbPath);
    raw.exec("CREATE TABLE unrelated (id INTEGER)");
    raw.close();

    await expect(openSqliteRunStore(dbPath)).rejects.toThrow(
      /Refusing to initialize an existing database/,
    );
  });

  it("reports corrupt records explicitly and never overwrites them", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, (store) => store.admit(spec("run_corrupt")));

    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE runs SET record_json = ? WHERE run_id = ?")
      .run("{not json", "run_corrupt");

    await withStore(dbPath, async (store) => {
      await expect(store.get("run_corrupt")).rejects.toThrow(/corrupt/);
      await expect(store.list()).rejects.toThrow(/corrupt/);
      // The failed admission is a transaction error: the store must not
      // "repair" the row by overwriting it with a fresh record.
      await expect(store.admit(spec("run_corrupt"))).rejects.toThrow(/corrupt/);
    });

    const row = raw
      .prepare("SELECT record_json FROM runs WHERE run_id = ?")
      .get("run_corrupt") as { record_json: string };
    raw.close();
    expect(row.record_json).toBe("{not json");
  });

  it("reports schema-invalid records explicitly and never overwrites them", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const admitted = await withStore(dbPath, (store) =>
      store.admit(spec("run_schema_invalid")),
    );

    // Valid JSON that violates the stored record schema (unknown status) —
    // distinct from unparseable JSON.
    const raw = rawDb(dbPath);
    raw
      .prepare("UPDATE runs SET record_json = ? WHERE run_id = ?")
      .run(
        JSON.stringify({ ...admitted.record, status: "exploded" }),
        "run_schema_invalid",
      );

    await withStore(dbPath, async (store) => {
      await expect(store.get("run_schema_invalid")).rejects.toThrow(/corrupt/);
      await expect(store.list()).rejects.toThrow(/corrupt/);
      await expect(store.admit(spec("run_schema_invalid"))).rejects.toThrow(
        /corrupt/,
      );
    });

    const row = raw
      .prepare("SELECT record_json FROM runs WHERE run_id = ?")
      .get("run_schema_invalid") as { record_json: string };
    raw.close();
    expect(JSON.parse(row.record_json).status).toBe("exploded");
  });

  it("leaves the previous status untouched when a transition is rejected", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, async (store) => {
      const a = await store.admit(spec("run_partial"));
      await store.transition("run_partial", a.record.attemptId, "running");

      await expect(
        store.transition("run_partial", "exec_wrong", "completed"),
      ).rejects.toThrow();

      const record = await store.get("run_partial");
      expect(record?.status).toBe("running");
      expect(record?.attemptId).toBe(a.record.attemptId);
    });
  });
});

describe("injected write failures roll back without accepting execution", () => {
  it("rolls back admission when the insert fails", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    await withStore(dbPath, (store) => store.admit(spec("run_insert_seed")));

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_insert BEFORE INSERT ON runs " +
        "BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(store.admit(spec("run_insert_blocked"))).rejects.toThrow();
      expect(await store.get("run_insert_blocked")).toBeUndefined();
      expect(await store.list()).toHaveLength(1);
    });
  });

  it("rolls back a status transition when the update fails", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const admitted = await withStore(dbPath, (store) =>
      store.admit(spec("run_update_blocked")),
    );

    const raw = rawDb(dbPath);
    raw.exec(
      "CREATE TRIGGER reject_update BEFORE UPDATE ON runs " +
        "BEGIN SELECT RAISE(ABORT, 'injected update failure'); END",
    );
    raw.close();

    await withStore(dbPath, async (store) => {
      await expect(
        store.transition(
          "run_update_blocked",
          admitted.record.attemptId,
          "running",
        ),
      ).rejects.toThrow();
      const record = await store.get("run_update_blocked");
      expect(record?.status).toBe("admitted");
      expect(record?.attemptId).toBe(admitted.record.attemptId);
      expect(record?.updatedAt).toBe(admitted.record.updatedAt);
    });
  });
});

describe("concurrent admission across connections", () => {
  it("yields exactly one winner between two in-process connections", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const a = await openSqliteRunStore(dbPath);
    const b = await openSqliteRunStore(dbPath);
    try {
      const [first, second] = await Promise.all([
        a.admit(spec("run_race")),
        b.admit(spec("run_race")),
      ]);
      const winners = [first, second].filter((r) => r.created);
      expect(winners).toHaveLength(1);
      const loser = [first, second].find((r) => !r.created)!;
      expect(loser.record.attemptId).toBe(winners[0]!.record.attemptId);
      expect(loser.record.sessionId).toBe(winners[0]!.record.sessionId);
      expect((await a.list()).length).toBe(1);
    } finally {
      a.close();
      b.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Real subprocess contention. The contender script is generated into a temp
// fixture directory at test time and imports the real store source, so the
// child processes exercise the actual admission path, not a test double.
// Bun children run the TypeScript source directly; Node children run a
// bundle produced once by `bun build --target=node` (.mjs for ESM output).
// ---------------------------------------------------------------------------

const RUN_ID = "run_subprocess_race";
const contender = (() => {
  let script: string | undefined;
  let bundle: string | undefined;
  let cwd: string | undefined;
  return {
    async setup() {
      if (script) return;
      const dir = tempDir("runstore-fixture-");
      cwd = tempDir("runstore-cwd-");
      script = join(dir, "contender.ts");
      const storeSource = join(import.meta.dirname, "sqliteRunStore.ts");
      writeFileSync(
        script,
        `
import { openSqliteRunStore } from ${JSON.stringify(storeSource)};

const baseSpec = ${JSON.stringify(baseSpec("TEMPLATE", cwd))};
const [mode, dbPath, runId, variant] = process.argv.slice(2);
const spec = { ...baseSpec, runId };

const store = await openSqliteRunStore(dbPath);
try {
  if (mode === "admit") {
    if (variant === "changed") spec.prompt = "A different objective entirely";
    const result = await store.admit(spec);
    console.log(JSON.stringify({
      created: result.created,
      attemptId: result.record.attemptId,
      sessionId: result.record.sessionId,
    }));
    store.close();
  } else if (mode === "hold") {
    const admitted = await store.admit(spec);
    const record = await store.transition(runId, admitted.record.attemptId, "running");
    console.log(JSON.stringify({
      created: admitted.created,
      attemptId: record.attemptId,
      status: record.status,
    }));
    setInterval(() => {}, 1000);
  } else {
    throw new Error("unknown mode: " + mode);
  }
} catch (error) {
  console.error(String(error));
  process.exitCode = 1;
  store.close();
}
`,
      );
      const built = spawnSync(
        "bun",
        [
          "build",
          "--target=node",
          "--outfile",
          join(dir, "contender.mjs"),
          script,
        ],
        { encoding: "utf8" },
      );
      if (built.status === 0) bundle = join(dir, "contender.mjs");
    },
    script(): string {
      if (!script) throw new Error("contender fixture not built");
      return script;
    },
    bundle(): string {
      if (!bundle)
        throw new Error("bun build failed to produce the node bundle");
      return bundle;
    },
    specFor(runId: string) {
      if (!cwd) throw new Error("contender fixture not built");
      return baseSpec(runId, cwd);
    },
  };
})();

function runChild(
  command: string,
  args: string[],
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("subprocess contention and crash persistence", () => {
  beforeAll(() => contender.setup());

  it("admits exactly one winner among simultaneous bun subprocesses", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const results = await Promise.all(
      Array.from({ length: 7 }, () =>
        runChild("bun", [contender.script(), "admit", dbPath, RUN_ID]),
      ),
    );

    for (const result of results) expect(result.code).toBe(0);
    const records = results.map((r) => JSON.parse(r.stdout.trim()));
    const winners = records.filter((r) => r.created);
    expect(winners).toHaveLength(1);
    for (const record of records) {
      expect(record.attemptId).toBe(winners[0].attemptId);
      expect(record.sessionId).toBe(winners[0].sessionId);
    }

    await withStore(dbPath, async (store) => {
      expect((await store.list()).length).toBe(1);
    });
  });

  it("admits exactly one winner among mixed bun and node subprocesses", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");
    const results = await Promise.all([
      ...Array.from({ length: 4 }, () =>
        runChild("bun", [contender.script(), "admit", dbPath, RUN_ID]),
      ),
      ...Array.from({ length: 3 }, () =>
        runChild("node", [contender.bundle(), "admit", dbPath, RUN_ID]),
      ),
    ]);

    for (const result of results) {
      expect(result.code, `contender failed: ${result.stderr}`).toBe(0);
    }
    const records = results.map((r) => JSON.parse(r.stdout.trim()));
    const winner = records.find((r) => r.created);
    expect(winner).toBeDefined();
    expect(records.filter((r) => r.created)).toHaveLength(1);
    for (const record of records) {
      expect(record.attemptId).toBe(winner!.attemptId);
    }

    await withStore(dbPath, async (store) => {
      expect((await store.list()).length).toBe(1);
    });
  });

  it("keeps the admitted/running record after a killed subprocess, without restart", async () => {
    const dbPath = join(tempDir("runstore-db-"), "runs.sqlite");

    holdChild = spawn("bun", [contender.script(), "hold", dbPath, RUN_ID], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    holdChild.stdout!.on("data", (chunk) => (stdout += chunk));
    const marker = await new Promise<{ attemptId: string; status: string }>(
      (resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`contender produced no marker: ${stdout}`)),
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
      },
    );
    expect(marker.status).toBe("running");

    holdChild.kill("SIGKILL");
    await new Promise<void>((resolve) =>
      holdChild!.on("close", () => resolve()),
    );

    await withStore(dbPath, async (store) => {
      const record = await store.get(RUN_ID);
      expect(record?.status).toBe("running");
      expect(record?.attemptId).toBe(marker.attemptId);

      // Re-running the same command must not restart the assessment: the
      // duplicate returns the original attempt, not a new one.
      const again = await store.admit(contender.specFor(RUN_ID));
      expect(again.created).toBe(false);
      expect(again.record.attemptId).toBe(marker.attemptId);
    });
  });
});
