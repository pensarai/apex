/**
 * C3 recovery acceptance through the public API with real SQLite, a real
 * Bun child SIGKILL, and a loopback POST counter. The child fixture
 * (src/core/runtime/testfixtures/recoveryChild.ts) is a direct Bun
 * executable running the real runRecordedAgent path — no nested vitest
 * runner, so SIGKILL hits the actual executor. Resume happens in-process
 * here through resumeRecordedAgent with only the expensive seams mocked
 * (session get into the shared temp fixture, resumed agent consuming
 * saved results).
 *
 * This is fixture-provider validation: no live LLM calls, no token spend.
 * The model id claude-haiku-4-5 selects the reconstruction-eligible direct
 * Anthropic (thinking-off) path per the C3 contract.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const sessionGet = vi.hoisted(() => vi.fn());
const runAgent = vi.hoisted(() => vi.fn());

vi.mock("../session", () => ({ get: sessionGet, create: sessionGet }));
vi.mock("./offesecAgent", () => ({ runOffensiveSecurityAgent: runAgent }));

import { buildSessionWorkspaceSection } from "../agents/offSecAgent";
import { getInferenceRecorder } from "../ai";
import { startInferenceAttempt } from "../ai/inference-attempt";
import { openSqliteRunStore } from "../runtime/sqliteRunStore";
import {
  RunRecoveryBlockedError,
  resumeRecordedAgent,
  runRecordedAgent,
} from "./recordedRun";

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

const RUN_RESULT = { streamResult: {}, session: {} } as never;

let tempDirs: string[] = [];
let children: ChildProcess[] = [];
let target: Server | undefined;
let targetHits = 0;
let targetPort = 0;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function specFor(
  cwd: string,
  runId: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId,
    prompt: "Request the target homepage once and summarize the response.",
    target: `http://127.0.0.1:${targetPort}`,
    model: "claude-haiku-4-5",
    activeTools: ["http_request"],
    environment: { kind: "local", cwd },
    scope: {
      version: 1,
      allowedHosts: ["127.0.0.1"],
      allowedPorts: [targetPort],
      strictScope: true,
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
    },
    credentialRefs: [],
    limits: { maxModelAttempts: 4 },
    ...overrides,
  };
}

/**
 * Spawn the child fixture as a direct Bun executable — no nested vitest
 * runner or worker grandchildren, so SIGKILL terminates the actual
 * executor. The child prints `MARKER:<scenario>:<status>` at its stall
 * point; timeout is cleared on every exit path.
 */
function spawnChild(
  scenario: string,
  env: Record<string, string>,
): {
  child: ChildProcess;
  marker: Promise<string>;
} {
  const fixture = join(
    import.meta.dirname,
    "../runtime/testfixtures/recoveryChild.ts",
  );
  const child = spawn("bun", [fixture], {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      APEX_RECOVERY_SCENARIO: scenario,
      ...env,
    },
  });
  children.push(child);
  const marker = new Promise<string>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      fn();
    };
    child.stdout!.on("data", (c) => {
      stdout += c;
      const m = stdout.match(/MARKER:([a-z-]+):(\d+)/);
      if (m) finish(() => resolve(m[0]));
    });
    child.stderr!.on("data", (c) => (stderr += c));
    child.on("close", () =>
      finish(() =>
        reject(
          new Error(
            `child exited before marker.\nstdout=${stdout}\nstderr=${stderr}`,
          ),
        ),
      ),
    );
    child.on("error", (e) => finish(() => reject(e)));
    timer = setTimeout(
      () =>
        finish(() =>
          reject(
            new Error(
              `child produced no marker.\nstdout=${stdout}\nstderr=${stderr}`,
            ),
          ),
        ),
      20000,
    );
  });
  return { child, marker };
}

async function killAndAwait(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const closed = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("Crash-test executor did not exit")),
      5000,
    );
    child.once("close", (_code, signal) => {
      clearTimeout(timer);
      expect(signal).toBe("SIGKILL");
      resolve();
    });
  });
  child.kill("SIGKILL");
  await closed;
}

beforeAll(async () => {
  tempDirs = [];
  children = [];
  targetHits = 0;
  target = createServer((req, res) => {
    if (req.method === "POST") {
      targetHits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, hits: targetHits }));
      return;
    }
    res.writeHead(204);
    res.end();
  });
  await new Promise<void>((resolve) => target!.listen(0, "127.0.0.1", resolve));
  targetPort = (target!.address() as { port: number }).port;
});

afterAll(async () => {
  for (const child of children) await killAndAwait(child);
  if (target) {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 5000);
      target!.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

let store: Store | undefined;

afterEach(() => {
  store?.close();
  store = undefined;
});

/** Shared fixture directories for one child run + parent resume. */
function fixtureDirs() {
  const base = tempDir("recovery-fixture-");
  const dbPath = join(base, "runs.sqlite");
  const dataDir = join(base, "pensar-data");
  const cwd = tempDir("recovery-cwd-");
  const sessionRoot = join(dataDir, "sessions", "ses_fixture_child");
  return { base, dbPath, dataDir, cwd, sessionRoot };
}

/**
 * Parent-side session.get returns the ACTUAL session.json the child
 * fixture persisted at its session root. The requested id must match the
 * saved id — never fabricate an alternate session.
 */
function mockSessionGet(sessionRoot: string) {
  sessionGet.mockImplementation(async (id: string) => {
    const saved = JSON.parse(
      readFileSync(join(sessionRoot, "session.json"), "utf8"),
    );
    if (saved.id !== id) {
      throw new Error(
        `session id mismatch: requested ${id}, fixture saved ${saved.id}`,
      );
    }
    return saved;
  });
}

describe("recovery through the public API", () => {
  it("a live worker's lock refuses resume", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const { child, marker } = spawnChild("crash-after-post", {
      APEX_RECOVERY_DB: dirs.dbPath,
      APEX_RECOVERY_DATA_DIR: dirs.dataDir,
      APEX_RECOVERY_CWD: dirs.cwd,
      APEX_RECOVERY_SESSION_ROOT: dirs.sessionRoot,
      APEX_RECOVERY_PORT: String(targetPort),
      APEX_RECOVERY_RUN_ID: "run_lock_live",
    });
    expect(await marker).toMatch(/^MARKER:crash-after-post:200$/);
    // The child is alive and (once enrolled) holds the execution lock.
    // Resume must refuse without acquiring, and never dispatch.
    await expect(
      resumeRecordedAgent({
        runId: "run_lock_live",
        store,
      }),
    ).rejects.toThrow();
    await killAndAwait(child);
  });

  it("crash after POST before settle: unknown outcome blocks, counter unchanged, no new grant", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const { child, marker } = spawnChild("crash-after-post", {
      APEX_RECOVERY_DB: dirs.dbPath,
      APEX_RECOVERY_DATA_DIR: dirs.dataDir,
      APEX_RECOVERY_CWD: dirs.cwd,
      APEX_RECOVERY_SESSION_ROOT: dirs.sessionRoot,
      APEX_RECOVERY_PORT: String(targetPort),
      APEX_RECOVERY_RUN_ID: "run_unknown_post",
    });
    expect(await marker).toMatch(/^MARKER:crash-after-post:200$/);
    const hitsAfterCrash = targetHits;
    await killAndAwait(child);

    // The journal shows the accepted intent with no committed outcome.
    const ops = await store.listToolOperations("run_unknown_post");
    expect(ops).toHaveLength(1);
    expect(ops[0]).toMatchObject({
      toolCallId: "tc_recovery_1",
      state: "started",
    });
    const attemptsBefore = (await store.listModelAttempts("run_unknown_post"))
      .length;
    const recordBefore = (await store.get("run_unknown_post"))!;

    // Resume blocks on the unknown outcome; no new model grant, no HTTP.
    mockSessionGet(dirs.sessionRoot);
    const blocked = await resumeRecordedAgent({
      runId: "run_unknown_post",
      store,
    }).catch((e: unknown) => e);
    expect(blocked).toBeInstanceOf(RunRecoveryBlockedError);
    // The blocker names the uncertain operation, not a vague refusal.
    expect((blocked as RunRecoveryBlockedError).blockers.join(" ")).toMatch(
      /unknown|started/i,
    );
    expect(targetHits).toBe(hitsAfterCrash);
    expect((await store.listModelAttempts("run_unknown_post")).length).toBe(
      attemptsBefore,
    );
    // A blocked resume claims nothing: no recovery history, no owner change.
    expect(await store.listRecoveries("run_unknown_post")).toEqual([]);
    const recordAfter = (await store.get("run_unknown_post"))!;
    expect(recordAfter.attemptId).toBe(recordBefore.attemptId);
    expect(recordAfter.status).toBe(recordBefore.status);
  });

  it("crash after settlement before checkpoint: resume reconstructs, consumes the saved receipt, completes fresh", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const { child, marker } = spawnChild("crash-after-settle", {
      APEX_RECOVERY_DB: dirs.dbPath,
      APEX_RECOVERY_DATA_DIR: dirs.dataDir,
      APEX_RECOVERY_CWD: dirs.cwd,
      APEX_RECOVERY_SESSION_ROOT: dirs.sessionRoot,
      APEX_RECOVERY_PORT: String(targetPort),
      APEX_RECOVERY_RUN_ID: "run_settled_crash",
    });
    expect(await marker).toMatch(/^MARKER:crash-after-settle:200$/);
    const hitsAfterCrash = targetHits;
    await killAndAwait(child);

    const preAttempts = await store.listModelAttempts("run_settled_crash");
    const preRecord = (await store.get("run_settled_crash"))!;
    const preContext = await store.getContext("run_settled_crash");
    expect(preContext).toBeDefined();

    // The resumed agent consumes the reconstructed exchange — the saved
    // receipt is in its messages; no HTTP re-execution. It exercises the
    // real inference recorder (reservation + settlement) and recomposes the
    // workspace suffix exactly as the wired agent does.
    let resumedMessages: unknown[] | undefined;
    let resumedSystem: string | undefined;
    runAgent.mockImplementationOnce(
      async (input: {
        messages?: unknown[];
        system?: string;
        session: { rootPath: string; scratchpadPath?: string } & Record<
          string,
          unknown
        >;
        activeTools: string[];
        contextRecorder: {
          checkpoint: (i: {
            messages: unknown[];
            system?: string;
          }) => Promise<void>;
        };
      }) => {
        resumedMessages = input.messages;
        resumedSystem = input.system;
        // The API supplies the base system WITHOUT the workspace suffix.
        expect((resumedSystem ?? "").includes("# Session Workspace")).toBe(
          false,
        );
        expect(resumedSystem).toContain(
          "Custom base system for recovery acceptance",
        );

        // Real reservation through the resumed inference recorder.
        const recorder = getInferenceRecorder();
        if (!recorder) throw new Error("no inference recorder in ALS context");
        const handle = startInferenceAttempt({
          operationKind: "agent.stream",
          requested: { provider: "anthropic", modelId: "claude-haiku-4-5" },
        });

        // The next checkpoint recomposes base + workspace suffix once —
        // same builder the real agent uses.
        const workspace = buildSessionWorkspaceSection(
          input.session as unknown as Parameters<
            typeof buildSessionWorkspaceSection
          >[0],
          dirs.cwd,
          input.activeTools,
        );
        await input.contextRecorder.checkpoint({
          messages: resumedMessages ?? [],
          system: `${resumedSystem}${workspace}`,
        });
        await recorder.beforeDispatch(handle.started);
        await input.contextRecorder.checkpoint({
          messages: [
            ...(resumedMessages ?? []),
            {
              role: "assistant",
              content: [{ type: "text", text: "Resumed." }],
            },
          ],
          system: `${resumedSystem}${workspace}`,
        });
        recorder.settle(
          handle.complete({
            tokens: {
              inclusiveInput: 80,
              uncachedInput: 80,
              cacheRead: 0,
              cacheWrite: 0,
              output: 9,
            },
          }),
        );
        return RUN_RESULT;
      },
    );
    mockSessionGet(dirs.sessionRoot);

    const outcome = await resumeRecordedAgent({
      runId: "run_settled_crash",
      store,
    });

    // Fresh execution id, same run and session, completed.
    expect(outcome.record.status).toBe("completed");
    expect(outcome.record.attemptId).not.toBe(preRecord.attemptId);
    expect(outcome.record.sessionId).toBe(preRecord.sessionId);
    // Budget preserved exactly: the prior reservation plus the resumed
    // run's own single dispatch — no more, no fewer.
    const postAttempts = await store.listModelAttempts("run_settled_crash");
    expect(postAttempts).toHaveLength(preAttempts.length + 1);
    expect(postAttempts.at(-1)?.context).toEqual({
      epoch: preContext!.epoch,
      revision: preContext!.revision + 1,
    });
    expect((await store.getContext("run_settled_crash"))?.revision).toBe(
      preContext!.revision + 2,
    );
    // No HTTP re-execution for the settled receipt.
    expect(targetHits).toBe(hitsAfterCrash);
    // The resumed agent saw the reconstructed tool exchange and the base
    // system without any workspace copy (the suffix is recomposed at
    // checkpoint time by the agent, not carried in input.system).
    const messages = resumedMessages as Array<{
      role: string;
      content?: unknown;
    }>;
    const toolMessage = messages.find((m) => m.role === "tool");
    expect(toolMessage).toBeDefined();
    expect((resumedSystem ?? "").split("# Session Workspace").length - 1).toBe(
      0,
    );
    // A recovery record exists linking the two attempts.
    const recoveries = await store.listRecoveries("run_settled_crash");
    expect(recoveries.length).toBe(1);
    expect(recoveries[0]).toMatchObject({
      fromAttemptId: preRecord.attemptId,
      toAttemptId: outcome.record.attemptId,
    });
  });
});

describe("resume blockers (legacy, stop, expired deadline, budget, evidence, context)", () => {
  it.each([
    "missing evidence",
    "corrupt context",
  ])("refuses %s before changing ownership", async (damage) => {
    const dirs = fixtureDirs();
    const runId = "run_damaged_recovery";
    store = await openSqliteRunStore(dirs.dbPath);
    const { child, marker } = spawnChild("crash-after-settle", {
      APEX_RECOVERY_DB: dirs.dbPath,
      APEX_RECOVERY_DATA_DIR: dirs.dataDir,
      APEX_RECOVERY_CWD: dirs.cwd,
      APEX_RECOVERY_SESSION_ROOT: dirs.sessionRoot,
      APEX_RECOVERY_PORT: String(targetPort),
      APEX_RECOVERY_RUN_ID: runId,
    });
    await marker;
    await killAndAwait(child);
    const before = await store.get(runId);
    const hits = targetHits;
    if (damage === "missing evidence") {
      expect(
        (await store.getEvidence(runId))?.files.map((ref) => ref.path),
      ).toContain("pocs/receipt.txt");
      rmSync(join(dirs.sessionRoot, "pocs", "receipt.txt"));
    } else {
      const { DatabaseSync } = createRequire(import.meta.url)(
        "node:sqlite",
      ) as typeof import("node:sqlite");
      const raw = new DatabaseSync(dirs.dbPath);
      try {
        raw
          .prepare("UPDATE run_context SET change_json = ? WHERE run_id = ?")
          .run("corrupt-json", runId);
      } finally {
        raw.close();
      }
    }
    mockSessionGet(dirs.sessionRoot);
    await expect(resumeRecordedAgent({ runId, store })).rejects.toThrow(
      damage === "missing evidence"
        ? /Evidence is unavailable/
        : /context is corrupt/,
    );
    expect((await store.get(runId))?.attemptId).toBe(before?.attemptId);
    expect(await store.listRecoveries(runId)).toEqual([]);
    expect(targetHits).toBe(hits);
  });

  it("a legacy unenrolled run cannot resume", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    // A genuinely legacy crashed run: admitted/running with journal rows
    // but no recovery enrollment (the pre-C3 shape — enrollment does not
    // exist for it and migration must not invent it).
    const admitted = await store.admit(
      specFor(dirs.cwd, "run_legacy_unenrolled") as never,
    );
    const attemptId = admitted.record.attemptId;
    await store.transition("run_legacy_unenrolled", attemptId, "running");
    await store.initializeToolJournal("run_legacy_unenrolled", attemptId);
    await store.commitContext("run_legacy_unenrolled", attemptId, 0, {
      kind: "replace",
      messages: [{ role: "user", content: "Request the target once." }],
      system: "legacy system",
    });
    // Simulated crash: no further writes; the run stays "running".

    mockSessionGet(dirs.sessionRoot);
    const blocked = await resumeRecordedAgent({
      runId: "run_legacy_unenrolled",
      store,
    }).catch((e: unknown) => e);
    expect(blocked).toBeInstanceOf(RunRecoveryBlockedError);
    expect(
      (await store.getRecoveryEnrollment("run_legacy_unenrolled")) ?? undefined,
    ).toBeUndefined();
  });

  it("a stopped run refuses resume", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    const { child, marker } = spawnChild("crash-after-settle", {
      APEX_RECOVERY_DB: dirs.dbPath,
      APEX_RECOVERY_DATA_DIR: dirs.dataDir,
      APEX_RECOVERY_CWD: dirs.cwd,
      APEX_RECOVERY_SESSION_ROOT: dirs.sessionRoot,
      APEX_RECOVERY_PORT: String(targetPort),
      APEX_RECOVERY_RUN_ID: "run_stopped_block",
    });
    expect(await marker).toMatch(/^MARKER:crash-after-settle:200$/);

    // The client stops the run while the executor is stalled.
    const control = await store.getControl("run_stopped_block");
    await store.requestControl(
      "run_stopped_block",
      "stop",
      control?.revision ?? 0,
    );
    await killAndAwait(child);

    mockSessionGet(dirs.sessionRoot);
    await expect(
      resumeRecordedAgent({ runId: "run_stopped_block", store }),
    ).rejects.toThrow();
  });

  it("an expired deadline blocks resume before dispatch", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    // A run whose absolute deadline is already in the past: admitted with
    // the expired deadline from the start (the child is never spawned —
    // the deadline blocks before any dispatch).
    const outcome = await runRecordedAgent({
      spec: specFor(dirs.cwd, "run_expired_deadline", {
        limits: {
          maxModelAttempts: 4,
          deadlineAt: new Date(Date.now() - 60_000).toISOString(),
        },
      }),
      store,
    });
    // The fresh run itself is cancelled by the expired deadline.
    expect(outcome.record.status).toBe("cancelled");
    mockSessionGet(dirs.sessionRoot);
    await expect(
      resumeRecordedAgent({ runId: "run_expired_deadline", store }),
    ).rejects.toThrow();
  });

  it("an exhausted model budget blocks resume before dispatch", async () => {
    const dirs = fixtureDirs();
    store = await openSqliteRunStore(dirs.dbPath);
    // The child runs with a one-attempt budget: its own dispatch reservation
    // exhausts it before the stall. (Direct parent-side startModelAttempt is
    // refused — enrolled runs require the execution lock.)
    const { child, marker } = spawnChild("crash-after-settle", {
      APEX_RECOVERY_DB: dirs.dbPath,
      APEX_RECOVERY_DATA_DIR: dirs.dataDir,
      APEX_RECOVERY_CWD: dirs.cwd,
      APEX_RECOVERY_SESSION_ROOT: dirs.sessionRoot,
      APEX_RECOVERY_PORT: String(targetPort),
      APEX_RECOVERY_RUN_ID: "run_budget_exhausted",
      APEX_RECOVERY_MAX_ATTEMPTS: "1",
    });
    expect(await marker).toMatch(/^MARKER:crash-after-settle:200$/);
    await killAndAwait(child);

    const attempts = await store.listModelAttempts("run_budget_exhausted");
    expect(attempts).toHaveLength(1); // the budget is exhausted

    mockSessionGet(dirs.sessionRoot);
    const blocked = await resumeRecordedAgent({
      runId: "run_budget_exhausted",
      store,
    }).catch((e: unknown) => e);
    expect(blocked).toBeInstanceOf(RunRecoveryBlockedError);
    expect((blocked as Error).message).toContain("allowance is exhausted");
  });
});
