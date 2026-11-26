import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runRecordedAgent = vi.hoisted(() => vi.fn());
const serveLocalRunWorker = vi.hoisted(() => vi.fn());
const launchLocalWorker = vi.hoisted(() => vi.fn());
const resolveWorkerExecutable = vi.hoisted(() => vi.fn());
const workerRequest = vi.hoisted(() => vi.fn());
const resumeRecordedAgent = vi.hoisted(() => vi.fn());
const inspectSessionEvidence = vi.hoisted(() => vi.fn());
const openSqliteRunStore = vi.hoisted(() => vi.fn());
const configGet = vi.hoisted(() => vi.fn());
const buildAuthConfig = vi.hoisted(() => vi.fn());

vi.mock("../core/api", () => {
  class RunRecoveryBlockedError extends Error {
    constructor(readonly blockers: string[]) {
      super(`Run recovery blocked: ${blockers.join("; ")}`);
      this.name = "RunRecoveryBlockedError";
    }
  }
  return {
    runRecordedAgent,
    resumeRecordedAgent,
    inspectSessionEvidence,
    serveLocalRunWorker,
    RunRecoveryBlockedError,
  };
});
const { RunRecoveryBlockedError } = await import("../core/api");
vi.mock("../core/runtime/sqliteRunStore", () => ({ openSqliteRunStore }));
vi.mock("../core/runtime/launchLocalWorker", () => ({
  launchLocalWorker,
  resolveWorkerExecutable,
}));
vi.mock("../core/runtime/localWorkerTransport", () => ({
  workerRequest,
  LocalWorkerTransportError: class LocalWorkerTransportError extends Error {
    readonly code?: string;
    readonly uncertain: boolean;
    constructor(
      message: string,
      options: { code?: string; uncertain?: boolean } = {},
    ) {
      super(message);
      this.name = "LocalWorkerTransportError";
      this.code = options.code;
      this.uncertain = options.uncertain ?? false;
    }
  },
}));
vi.mock("../core/config", () => ({ config: { get: configGet } }));
vi.mock("../core/ai", () => ({ buildAuthConfig }));

const { runAgentRunsCommand } = await import("./agent-runs");
const { AgentEventBus } = await import("../core/eventBus");

function makeStore() {
  return {
    list: vi.fn(),
    get: vi.fn(),
    getContext: vi.fn(),
    getEvidence: vi.fn(),
    listModelAttempts: vi.fn(async () => []),
    listRetries: vi.fn(async () => []),
    hasToolJournal: vi.fn(async () => false),
    listToolOperations: vi.fn(async () => []),
    getControl: vi.fn(),
    requestControl: vi.fn(),
    resolveApproval: vi.fn(),
    listApprovals: vi.fn(async () => []),
    getRecoveryEnrollment: vi.fn(),
    listRecoveries: vi.fn(async () => []),
    close: vi.fn(),
  };
}

// Inferred per-spy types: `ReturnType<typeof vi.spyOn>` cannot carry the
// overloaded process.stderr.write signature.
function spyConsoleLog() {
  return vi.spyOn(console, "log").mockImplementation(() => {});
}

function spyStderrWrite() {
  return vi.spyOn(process.stderr, "write").mockImplementation(() => true);
}

let store: ReturnType<typeof makeStore>;
let log: ReturnType<typeof spyConsoleLog>;
let stderrWrite: ReturnType<typeof spyStderrWrite>;
let tempDirs: string[];

function specFile(spec: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "agent-runs-cli-"));
  tempDirs.push(dir);
  const path = join(dir, "spec.json");
  writeFileSync(path, JSON.stringify(spec), "utf8");
  return path;
}

function output(): string {
  return log.mock.calls.map((c) => c.join("")).join("\n");
}

function snapshotSignals() {
  return {
    sigint: process.listeners("SIGINT"),
    sigterm: process.listeners("SIGTERM"),
  };
}

function addedSince<T>(current: T[], before: T[]): T[] {
  return current.filter((fn) => !before.includes(fn));
}

function assertSignalsRestored(before: ReturnType<typeof snapshotSignals>) {
  const sigint = process.listeners("SIGINT");
  const sigterm = process.listeners("SIGTERM");
  expect(sigint.length).toBe(before.sigint.length);
  expect(sigterm.length).toBe(before.sigterm.length);
  for (const fn of before.sigint) expect(sigint).toContain(fn);
  for (const fn of before.sigterm) expect(sigterm).toContain(fn);
}

beforeEach(() => {
  vi.clearAllMocks();
  store = makeStore();
  openSqliteRunStore.mockResolvedValue(store);
  configGet.mockResolvedValue({});
  buildAuthConfig.mockReturnValue({ marker: "auth-config" });
  log = spyConsoleLog();
  stderrWrite = spyStderrWrite();
  tempDirs = [];
});

afterEach(() => {
  vi.unstubAllEnvs();
  log.mockRestore();
  stderrWrite.mockRestore();
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("help and invalid arguments open no store", () => {
  it.each([
    [["--help"]],
    [["help"]],
    [[]],
  ])("prints help for %j", async (args) => {
    await runAgentRunsCommand(args);

    expect(output()).toContain("Usage:");
    expect(output()).toContain("agent-runs");
    expect(openSqliteRunStore).not.toHaveBeenCalled();
  });

  it.each([
    [["bogus"]],
    [["show"]],
    [["start"]],
    [["list", "extra"]],
    [["show", "a", "b"]],
    [["list", "--spec", "spec.json"]],
    [["pause"]],
    [["stop"]],
    [["approve", "run-1"]],
    [["reject", "run-1"]],
    [["approve", "run-1", "ap-1", "extra"]],
    [["show", "run-1", "--approval", "ap-1"]],
    [["list", "--approval", "ap-1"]],
    [["pause", "run-1", "--spec", "spec.json"]],
    [["stop", "run-1", "--control"]],
    [["start", "--spec", "spec.json", "--approval", "ap-1"]],
    [["resume"]],
    [["resume", "run-1", "extra"]],
    [["list", "--recovery"]],
    [["resume", "run-1", "--spec", "spec.json"]],
    [["pause", "run-1", "--recovery"]],
    [["resume", "run-1", "--approval", "ap-1"]],
    [["start", "--spec", "spec.json", "--recovery"]],
  ])("rejects %j without opening the store", async (args) => {
    await expect(runAgentRunsCommand(args)).rejects.toThrow(
      /Invalid agent-runs arguments/,
    );

    expect(openSqliteRunStore).not.toHaveBeenCalled();
  });
});

describe("list", () => {
  it("prints records as JSON and closes the store", async () => {
    store.list.mockResolvedValue([{ runId: "run-1", status: "running" }]);

    await runAgentRunsCommand(["list", "--store", "/tmp/custom.db"]);

    expect(openSqliteRunStore).toHaveBeenCalledWith("/tmp/custom.db");
    expect(output()).toContain('"runId": "run-1"');
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("closes the store when listing fails", async () => {
    store.list.mockRejectedValue(new Error("store unreadable"));

    await expect(runAgentRunsCommand(["list"])).rejects.toThrow(
      "store unreadable",
    );

    expect(store.close).toHaveBeenCalledTimes(1);
  });
});

describe("show", () => {
  it("checks evidence at its persisted location and reports missing files", async () => {
    const snapshot = {
      rootPath: "/saved/session",
      files: [{ path: "plan.md", sha256: "a".repeat(64), bytes: 3 }],
    };
    store.get.mockResolvedValue({ status: "running" });
    store.getEvidence.mockResolvedValue(snapshot);
    inspectSessionEvidence.mockResolvedValue([
      { ref: snapshot.files[0], status: "missing" },
    ]);
    await runAgentRunsCommand(["show", "run-1", "--evidence"]);
    expect(inspectSessionEvidence).toHaveBeenCalledWith(
      snapshot,
      snapshot.files,
    );
    expect(JSON.parse(output()).evidence.files[0].status).toBe("missing");
  });
  it("includes the committed context only when requested", async () => {
    const context = {
      epoch: 2,
      revision: 7,
      system: null,
      messages: [{ role: "user", content: "compacted objective" }],
    };
    store.get.mockResolvedValue({ status: "running" });
    store.getContext.mockResolvedValue(context);
    await runAgentRunsCommand(["show", "run-1", "--context"]);
    expect(JSON.parse(output()).context).toEqual(context);
    expect(store.getContext).toHaveBeenCalledWith("run-1");
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("prints the record and closes the store", async () => {
    store.get.mockResolvedValue({ runId: "run-1", status: "completed" });

    await runAgentRunsCommand(["show", "run-1"]);

    expect(store.get).toHaveBeenCalledWith("run-1");
    expect(output()).toContain('"status": "completed"');
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("errors for a missing run and still closes the store", async () => {
    store.get.mockResolvedValue(null);

    await expect(runAgentRunsCommand(["show", "run-404"])).rejects.toThrow(
      "Run not found: run-404",
    );

    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("closes the store when the read fails", async () => {
    store.get.mockRejectedValue(new Error("corrupt record"));

    await expect(runAgentRunsCommand(["show", "run-1"])).rejects.toThrow(
      "corrupt record",
    );

    expect(store.close).toHaveBeenCalledTimes(1);
  });
});

describe("start", () => {
  const SPEC = {
    runId: "run-1",
    model: "claude-sonnet-4-6",
    prompt: "test the target",
    tools: ["read_file"],
    scope: { target: "https://example.com" },
  };

  it("reads the spec file and passes exact opts to the recorded run", async () => {
    runRecordedAgent.mockResolvedValue({
      started: true,
      record: { runId: "run-1", status: "running" },
    });
    const before = snapshotSignals();

    await runAgentRunsCommand(["start", "--spec", specFile(SPEC)]);

    expect(openSqliteRunStore).toHaveBeenCalledWith(undefined);
    expect(runRecordedAgent).toHaveBeenCalledTimes(1);
    const opts = runRecordedAgent.mock.calls[0][0];
    expect(opts.spec).toEqual(SPEC);
    expect(opts.store).toBe(store);
    expect(opts.authConfig).toEqual({ marker: "auth-config" });
    expect(opts.eventBus).toBeInstanceOf(AgentEventBus);
    expect(opts.abortSignal).toBeInstanceOf(AbortSignal);
    expect(opts.abortSignal.aborted).toBe(false);
    expect(output()).toContain('"started": true');
    expect(store.close).toHaveBeenCalledTimes(1);
    assertSignalsRestored(before);
  });

  it("aborts the run's signal from the installed SIGINT listener", async () => {
    runRecordedAgent.mockImplementation(
      (opts: { abortSignal: AbortSignal }) =>
        new Promise((resolve) => {
          opts.abortSignal.addEventListener("abort", () =>
            resolve({ started: true, record: { runId: "run-1" } }),
          );
        }),
    );
    const before = snapshotSignals();

    const pending = runAgentRunsCommand(["start", "--spec", specFile(SPEC)]);
    await vi.waitFor(() => expect(runRecordedAgent).toHaveBeenCalled());

    const added = addedSince(process.listeners("SIGINT"), before.sigint);
    expect(added.length).toBe(1);
    added[0]("SIGINT");

    await pending;
    expect(runRecordedAgent.mock.calls[0][0].abortSignal.aborted).toBe(true);
    assertSignalsRestored(before);
  });

  it("unsubscribes text-delta output when the run settles", async () => {
    runRecordedAgent.mockResolvedValue({
      started: true,
      record: { runId: "run-1" },
    });
    const before = snapshotSignals();

    await runAgentRunsCommand(["start", "--spec", specFile(SPEC)]);

    const bus = runRecordedAgent.mock.calls[0][0].eventBus;
    bus.emit("text-delta", { text: "straggler" });
    expect(stderrWrite).not.toHaveBeenCalledWith("straggler");
    assertSignalsRestored(before);
  });

  it("removes listeners and closes the store when the run fails", async () => {
    runRecordedAgent.mockRejectedValue(new Error("execution failed"));
    const before = snapshotSignals();

    await expect(
      runAgentRunsCommand(["start", "--spec", specFile(SPEC)]),
    ).rejects.toThrow("execution failed");

    assertSignalsRestored(before);
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("closes the store when the spec file cannot be read", async () => {
    await expect(
      runAgentRunsCommand(["start", "--spec", join(tmpdir(), "no-such-spec")]),
    ).rejects.toThrow();

    expect(runRecordedAgent).not.toHaveBeenCalled();
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("closes the store when the spec is not valid JSON", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agent-runs-cli-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, "spec.json"), "{not json", "utf8");

    await expect(
      runAgentRunsCommand(["start", "--spec", join(dir, "spec.json")]),
    ).rejects.toThrow();

    expect(runRecordedAgent).not.toHaveBeenCalled();
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("closes the store when config cannot be read", async () => {
    configGet.mockRejectedValue(new Error("config unreadable"));

    await expect(
      runAgentRunsCommand(["start", "--spec", specFile(SPEC)]),
    ).rejects.toThrow("config unreadable");

    expect(runRecordedAgent).not.toHaveBeenCalled();
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("displays a duplicate result without starting another execution", async () => {
    runRecordedAgent.mockResolvedValue({
      started: false,
      record: { runId: "run-1", status: "completed" },
    });

    await runAgentRunsCommand(["start", "--spec", specFile(SPEC)]);

    expect(runRecordedAgent).toHaveBeenCalledTimes(1);
    expect(output()).toContain('"started": false');
    expect(output()).toContain('"status": "completed"');
    expect(store.close).toHaveBeenCalledTimes(1);
  });
});

describe("model inspection", () => {
  it("shows attempts, retry timing, and the remaining reservation allowance", async () => {
    store.get.mockResolvedValue({ spec: { limits: { maxModelAttempts: 2 } } });
    const attempt = {
      attempt: { lifecycle: "started", tokens: { output: null } },
    };
    store.listModelAttempts.mockResolvedValue([attempt] as never);
    store.listRetries.mockResolvedValue([
      { sequence: 1, delayMs: 1000 },
    ] as never);
    await runAgentRunsCommand(["show", "run_models", "--models"]);
    expect(JSON.parse(output()).models).toEqual({
      attempts: [attempt],
      retries: [{ sequence: 1, delayMs: 1000 }],
      limits: {
        maxModelAttempts: 2,
        reservedModelAttempts: 1,
        remainingModelAttempts: 1,
        deadlineAt: null,
      },
    });
    expect(store.close).toHaveBeenCalledOnce();
  });

  it("does not invent a limit for runs admitted without one", async () => {
    store.get.mockResolvedValue({ spec: {} });
    await runAgentRunsCommand(["show", "run_models", "--models"]);
    expect(
      JSON.parse(output()).models.limits.remainingModelAttempts,
    ).toBeNull();
    await expect(runAgentRunsCommand(["list", "--models"])).rejects.toThrow(
      "Invalid agent-runs arguments",
    );
  });
});

describe("tool inspection", () => {
  it("distinguishes pre-journal runs from an empty recorded journal", async () => {
    store.get.mockResolvedValue({ status: "running" });
    await runAgentRunsCommand(["show", "run_old", "--tools"]);
    expect(JSON.parse(output()).tools).toEqual({
      journaled: false,
      operations: [],
    });
    expect(store.hasToolJournal).toHaveBeenCalledWith("run_old");
    expect(store.listToolOperations).toHaveBeenCalledWith("run_old");
    expect(store.close).toHaveBeenCalledOnce();
  });

  it("exposes unfinished effects without presenting them as settled results", async () => {
    store.get.mockResolvedValue({ status: "running" });
    store.hasToolJournal.mockResolvedValue(true);
    const operation = {
      toolCallId: "tc_1",
      state: "outcome_unknown",
      input: { method: "POST" },
    };
    store.listToolOperations.mockResolvedValue([operation] as never);
    await runAgentRunsCommand(["show", "run_tool", "--tools"]);
    expect(JSON.parse(output()).tools).toEqual({
      journaled: true,
      operations: [operation],
    });
    await expect(runAgentRunsCommand(["list", "--tools"])).rejects.toThrow(
      "Invalid agent-runs arguments",
    );
  });
});

describe("show --control", () => {
  it("prints the control record and approvals", async () => {
    store.get.mockResolvedValue({ status: "running" });
    const control = {
      runId: "run-1",
      executionAttemptId: "exec-1",
      intent: "run",
      revision: 0,
      updatedAt: "2026-10-05T00:00:00.000Z",
    };
    store.getControl.mockResolvedValue(control);
    const pending = {
      approvalId: "ap-1",
      toolCallId: "tc_1",
      toolName: "http_request",
      state: "pending",
      createdAt: "2026-10-05T00:00:01.000Z",
    };
    store.listApprovals.mockResolvedValue([pending] as never);
    await runAgentRunsCommand(["show", "run-1", "--control"]);
    const parsed = JSON.parse(output());
    expect(parsed.control.record).toEqual(control);
    expect(parsed.control.approvals).toEqual([pending]);
    expect(store.getControl).toHaveBeenCalledWith("run-1");
    expect(store.listApprovals).toHaveBeenCalledWith("run-1");
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("prints null control for runs that were never enrolled", async () => {
    store.get.mockResolvedValue({ status: "completed" });
    store.getControl.mockResolvedValue(undefined);
    await runAgentRunsCommand(["show", "run-legacy", "--control"]);
    const parsed = JSON.parse(output());
    expect(parsed.control).toEqual({ record: null, approvals: [] });
  });

  it("does not read control state without the flag", async () => {
    store.get.mockResolvedValue({ status: "running" });
    await runAgentRunsCommand(["show", "run-1"]);
    expect(store.getControl).not.toHaveBeenCalled();
    expect(store.listApprovals).not.toHaveBeenCalled();
    expect(JSON.parse(output()).control).toBeUndefined();
  });

  it("surfaces a pending approval left by a lost client without inventing a decision", async () => {
    store.get.mockResolvedValue({ status: "running" });
    store.getControl.mockResolvedValue({ intent: "pause", revision: 1 });
    store.listApprovals.mockResolvedValue([
      {
        approvalId: "ap-2",
        state: "pending",
        createdAt: "2026-10-05T00:00:01.000Z",
        decidedAt: undefined,
      },
    ] as never);
    await runAgentRunsCommand(["show", "run-1", "--control"]);
    const approval = JSON.parse(output()).control.approvals[0];
    expect(approval.state).toBe("pending");
    expect(approval).not.toHaveProperty("decidedAt", expect.anything());
  });

  it("errors for a missing run and still closes the store", async () => {
    store.get.mockResolvedValue(null);
    await expect(
      runAgentRunsCommand(["show", "run-404", "--control"]),
    ).rejects.toThrow("Run not found: run-404");
    expect(store.close).toHaveBeenCalledTimes(1);
  });
});

describe("pause and stop", () => {
  it("prints the persisted request with the run's last saved status, not an instantaneous change", async () => {
    store.get.mockResolvedValue({ status: "running" });
    store.getControl.mockResolvedValue({ intent: "run", revision: 3 });
    store.requestControl.mockResolvedValue({
      runId: "run-1",
      intent: "pause",
      revision: 4,
    });
    await runAgentRunsCommand(["pause", "run-1"]);
    expect(store.requestControl).toHaveBeenCalledWith("run-1", "pause", 3);
    const parsed = JSON.parse(output());
    expect(parsed.status).toBe("running");
    expect(parsed.control.intent).toBe("pause");
    expect(parsed.control.revision).toBe(4);
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("stop requests with the current revision as its CAS expectation", async () => {
    store.get.mockResolvedValue({ status: "running" });
    store.getControl.mockResolvedValue({ intent: "pause", revision: 7 });
    store.requestControl.mockResolvedValue({ intent: "stop", revision: 8 });
    await runAgentRunsCommand(["stop", "run-1"]);
    expect(store.requestControl).toHaveBeenCalledWith("run-1", "stop", 7);
    expect(JSON.parse(output()).control.intent).toBe("stop");
  });

  it("rejects runs without a control record and closes the store", async () => {
    store.get.mockResolvedValue({ status: "running" });
    store.getControl.mockResolvedValue(undefined);
    await expect(runAgentRunsCommand(["pause", "run-legacy"])).rejects.toThrow(
      "Run has no control record: run-legacy",
    );
    expect(store.requestControl).not.toHaveBeenCalled();
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("propagates a CAS conflict without retrying", async () => {
    store.get.mockResolvedValue({ status: "running" });
    store.getControl.mockResolvedValue({ intent: "run", revision: 2 });
    store.requestControl.mockRejectedValue(
      new Error("control revision changed; re-read and retry"),
    );
    await expect(runAgentRunsCommand(["stop", "run-1"])).rejects.toThrow(
      "control revision changed; re-read and retry",
    );
    expect(store.requestControl).toHaveBeenCalledTimes(1);
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("errors for an unknown run before touching control state", async () => {
    store.get.mockResolvedValue(null);
    await expect(runAgentRunsCommand(["stop", "run-404"])).rejects.toThrow(
      "Run not found: run-404",
    );
    expect(store.getControl).not.toHaveBeenCalled();
  });
});

describe("approve and reject", () => {
  it("resolves an approval through the store and prints the decision", async () => {
    store.resolveApproval.mockResolvedValue({
      approvalId: "ap-1",
      state: "approved",
      decidedAt: "2026-10-05T00:00:02.000Z",
    });
    await runAgentRunsCommand(["approve", "run-1", "--approval", "ap-1"]);
    expect(store.resolveApproval).toHaveBeenCalledWith(
      "run-1",
      "ap-1",
      "approved",
    );
    expect(JSON.parse(output()).state).toBe("approved");
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("reject records a user_rejected denial", async () => {
    store.resolveApproval.mockResolvedValue({
      approvalId: "ap-1",
      state: "denied",
      reason: "user_rejected",
    });
    await runAgentRunsCommand(["reject", "run-1", "--approval", "ap-1"]);
    expect(store.resolveApproval).toHaveBeenCalledWith(
      "run-1",
      "ap-1",
      "denied",
    );
    expect(JSON.parse(output()).state).toBe("denied");
  });

  it("propagates conflicting resolution and stop rejections, closing the store", async () => {
    store.resolveApproval.mockRejectedValueOnce(
      new Error("approval already denied"),
    );
    await expect(
      runAgentRunsCommand(["approve", "run-1", "--approval", "ap-1"]),
    ).rejects.toThrow("approval already denied");

    store.resolveApproval.mockRejectedValueOnce(
      new Error("run is stopped; approvals cannot change"),
    );
    await expect(
      runAgentRunsCommand(["reject", "run-1", "--approval", "ap-1"]),
    ).rejects.toThrow("run is stopped; approvals cannot change");
    expect(store.close).toHaveBeenCalledTimes(2);
  });
});

describe("show --recovery", () => {
  it("prints the enrollment and the recovery history", async () => {
    store.get.mockResolvedValue({ status: "paused" });
    const enrollment = {
      schemaVersion: 1,
      runId: "run-1",
      protocol: 1,
      enrolledAt: "2026-10-05T00:00:00.000Z",
      executionAttemptId: "exec-1",
      environment: { sessionRootPath: "/sessions/run-1" },
    };
    const history = [
      {
        schemaVersion: 1,
        recoveryId: "rec-1",
        runId: "run-1",
        claimedAt: "2026-10-05T00:01:00.000Z",
        fromAttemptId: "exec-1",
        toAttemptId: "exec-2",
        fromContext: { epoch: 1, revision: 3 },
      },
    ];
    store.getRecoveryEnrollment.mockResolvedValue(enrollment);
    store.listRecoveries.mockResolvedValue(history as never);
    await runAgentRunsCommand(["show", "run-1", "--recovery"]);
    const parsed = JSON.parse(output());
    expect(parsed.recovery).toEqual({ enrollment, history });
    expect(store.getRecoveryEnrollment).toHaveBeenCalledWith("run-1");
    expect(store.listRecoveries).toHaveBeenCalledWith("run-1");
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("prints a null enrollment for runs admitted before recovery protocol", async () => {
    store.get.mockResolvedValue({ status: "completed" });
    store.getRecoveryEnrollment.mockResolvedValue(undefined);
    await runAgentRunsCommand(["show", "run-legacy", "--recovery"]);
    const parsed = JSON.parse(output());
    expect(parsed.recovery).toEqual({ enrollment: null, history: [] });
  });

  it("does not read recovery state without the flag", async () => {
    store.get.mockResolvedValue({ status: "running" });
    await runAgentRunsCommand(["show", "run-1"]);
    expect(store.getRecoveryEnrollment).not.toHaveBeenCalled();
    expect(store.listRecoveries).not.toHaveBeenCalled();
  });

  it("errors for a missing run and still closes the store", async () => {
    store.get.mockResolvedValue(null);
    await expect(
      runAgentRunsCommand(["show", "run-404", "--recovery"]),
    ).rejects.toThrow("Run not found: run-404");
    expect(store.close).toHaveBeenCalledTimes(1);
  });
});

describe("resume", () => {
  it("reuses the start execution wiring and passes exact opts", async () => {
    resumeRecordedAgent.mockResolvedValue({
      started: true,
      record: { runId: "run-1", status: "running" },
    });
    const before = snapshotSignals();

    await runAgentRunsCommand(["resume", "run-1", "--store", "/tmp/custom.db"]);

    expect(openSqliteRunStore).toHaveBeenCalledWith("/tmp/custom.db");
    expect(resumeRecordedAgent).toHaveBeenCalledTimes(1);
    const opts = resumeRecordedAgent.mock.calls[0][0];
    expect(opts.runId).toBe("run-1");
    expect(opts.store).toBe(store);
    expect(opts.authConfig).toEqual({ marker: "auth-config" });
    expect(opts.eventBus).toBeInstanceOf(AgentEventBus);
    expect(opts.abortSignal).toBeInstanceOf(AbortSignal);
    expect(opts.abortSignal.aborted).toBe(false);
    expect(runRecordedAgent).not.toHaveBeenCalled();
    expect(output()).toContain('"started": true');
    expect(store.close).toHaveBeenCalledTimes(1);
    assertSignalsRestored(before);
  });

  it("unsubscribes streamed text when the resumed run settles", async () => {
    resumeRecordedAgent.mockResolvedValue({
      started: true,
      record: { runId: "run-1" },
    });
    const before = snapshotSignals();

    await runAgentRunsCommand(["resume", "run-1"]);

    const bus = resumeRecordedAgent.mock.calls[0][0].eventBus;
    bus.emit("text-delta", { text: "straggler" });
    expect(stderrWrite).not.toHaveBeenCalledWith("straggler");
    assertSignalsRestored(before);
  });

  it("aborts the resumed run from the installed SIGINT listener", async () => {
    resumeRecordedAgent.mockImplementation(
      (opts: { abortSignal: AbortSignal }) =>
        new Promise((resolve) => {
          opts.abortSignal.addEventListener("abort", () =>
            resolve({ started: true, record: { runId: "run-1" } }),
          );
        }),
    );
    const before = snapshotSignals();

    const pending = runAgentRunsCommand(["resume", "run-1"]);
    await vi.waitFor(() => expect(resumeRecordedAgent).toHaveBeenCalled());

    const added = addedSince(process.listeners("SIGINT"), before.sigint);
    expect(added.length).toBe(1);
    added[0]("SIGINT");

    await pending;
    expect(resumeRecordedAgent.mock.calls[0][0].abortSignal.aborted).toBe(true);
    assertSignalsRestored(before);
  });

  it("removes listeners and closes the store when the resume fails", async () => {
    resumeRecordedAgent.mockRejectedValue(new Error("execution failed"));
    const before = snapshotSignals();

    await expect(runAgentRunsCommand(["resume", "run-1"])).rejects.toThrow(
      "execution failed",
    );

    assertSignalsRestored(before);
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("prints structured blockers for a RunRecoveryBlockedError and rethrows", async () => {
    resumeRecordedAgent.mockRejectedValue(
      new RunRecoveryBlockedError([
        "Session root does not match recovery enrollment",
        "Run has an outcome_unknown tool operation",
      ]),
    );
    const before = snapshotSignals();

    await expect(
      runAgentRunsCommand(["resume", "run-1"]),
    ).rejects.toBeInstanceOf(RunRecoveryBlockedError);

    const parsed = JSON.parse(output());
    expect(parsed.blocked).toBe(true);
    expect(parsed.blockers).toEqual([
      "Session root does not match recovery enrollment",
      "Run has an outcome_unknown tool operation",
    ]);
    assertSignalsRestored(before);
    expect(store.close).toHaveBeenCalledTimes(1);
  });

  it("closes the store when config cannot be read", async () => {
    configGet.mockRejectedValue(new Error("config unreadable"));

    await expect(runAgentRunsCommand(["resume", "run-1"])).rejects.toThrow(
      "config unreadable",
    );

    expect(resumeRecordedAgent).not.toHaveBeenCalled();
    expect(store.close).toHaveBeenCalledTimes(1);
  });
});

describe("worker route (hidden)", () => {
  it("serves the worker for --run and an absolute --store", async () => {
    serveLocalRunWorker.mockResolvedValue(undefined);

    await runAgentRunsCommand([
      "worker",
      "--run",
      "run-1",
      "--store",
      "/tmp/abs/runs.sqlite",
    ]);

    expect(serveLocalRunWorker).toHaveBeenCalledWith({
      runId: "run-1",
      databasePath: "/tmp/abs/runs.sqlite",
    });
    expect(openSqliteRunStore).not.toHaveBeenCalled();
  });

  it.each([
    [["worker"]],
    [["worker", "--run", "run-1"]],
    [["worker", "--store", "/tmp/abs/runs.sqlite"]],
    [["worker", "--run", "run-1", "--store", "/tmp/abs", "extra"]],
  ])("rejects %j without opening a store or spawning", async (args) => {
    await expect(runAgentRunsCommand(args)).rejects.toThrow(
      /agent-runs worker requires/,
    );
    expect(openSqliteRunStore).not.toHaveBeenCalled();
    expect(serveLocalRunWorker).not.toHaveBeenCalled();
  });
});

describe("start --detach", () => {
  const SPEC = {
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_detach",
    model: "claude-sonnet-4-6",
    prompt: "test the target",
    target: "https://example.com",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: "/tmp/target" },
    scope: { version: 1, strictScope: true },
  };

  it("launches a worker and dispatches the normalized start spec", async () => {
    launchLocalWorker.mockResolvedValue({
      socketPath: "/tmp/w/run_detach.sock",
      logPath: "/tmp/w/run_detach.log",
    });
    resolveWorkerExecutable.mockReturnValue({ command: "pensar" });
    workerRequest.mockResolvedValue({ phase: "executing" });

    await runAgentRunsCommand([
      "start",
      "--spec",
      specFile(SPEC),
      "--detach",
      "--store",
      "/tmp/abs/runs.sqlite",
    ]);

    expect(launchLocalWorker).toHaveBeenCalledWith({
      runId: "run_detach",
      databasePath: "/tmp/abs/runs.sqlite",
      executable: { command: "pensar" },
    });
    expect(workerRequest).toHaveBeenCalledTimes(1);
    const [socketPath, request] = workerRequest.mock.calls[0];
    expect(socketPath).toBe("/tmp/w/run_detach.sock");
    expect(request.method).toBe("start");
    expect(request.protocolVersion).toBe(1);
    expect(request.spec).toEqual({
      ...SPEC,
      schemaVersion: 1,
      configVersion: 1,
      credentialRefs: [],
      scope: {
        ...SPEC.scope,
        allowedHosts: [],
        allowedPorts: [],
        allowDestructiveActions: false,
        allowRateLimitTesting: false,
      },
    });
    const parsed = JSON.parse(output());
    expect(parsed.detached).toBe(true);
    expect(parsed.socketPath).toBe("/tmp/w/run_detach.sock");
    expect(parsed.logPath).toBe("/tmp/w/run_detach.log");
    expect(parsed.snapshot.phase).toBe("executing");
    // No in-process execution path was taken.
    expect(runRecordedAgent).not.toHaveBeenCalled();
  });

  it("propagates launcher failures without dispatching", async () => {
    launchLocalWorker.mockRejectedValue(
      new Error("Worker for run_detach did not become ready within 15ms"),
    );

    await expect(
      runAgentRunsCommand(["start", "--spec", specFile(SPEC), "--detach"]),
    ).rejects.toThrow(/did not become ready/);
    expect(workerRequest).not.toHaveBeenCalled();
  });

  it("does not retry a lost start acknowledgement", async () => {
    launchLocalWorker.mockResolvedValue({
      socketPath: "/tmp/w/run_detach.sock",
      logPath: "/tmp/w/run_detach.log",
    });
    workerRequest.mockRejectedValue(
      Object.assign(new Error("request outcome uncertain"), {
        uncertain: true,
      }),
    );

    await expect(
      runAgentRunsCommand(["start", "--spec", specFile(SPEC), "--detach"]),
    ).rejects.toThrow("request outcome uncertain");
    expect(workerRequest).toHaveBeenCalledTimes(1);
  });
});

describe("resume --detach", () => {
  it("launches a worker and dispatches resume with the saved attempt id", async () => {
    store.get.mockResolvedValue({
      runId: "run-1",
      attemptId: "exec_00000000-0000-4000-8000-000000000001",
      status: "paused",
    });
    launchLocalWorker.mockResolvedValue({
      socketPath: "/tmp/w/run-1.sock",
      logPath: "/tmp/w/run-1.log",
    });
    resolveWorkerExecutable.mockReturnValue({ command: "pensar" });
    workerRequest.mockResolvedValue({ phase: "executing" });

    await runAgentRunsCommand(["resume", "run-1", "--detach"]);

    expect(launchLocalWorker).toHaveBeenCalledWith({
      runId: "run-1",
      databasePath: expect.any(String),
      executable: { command: "pensar" },
    });
    const [socketPath, request] = workerRequest.mock.calls[0];
    expect(socketPath).toBe("/tmp/w/run-1.sock");
    expect(request).toEqual({
      protocolVersion: 1,
      method: "resume",
      expectedAttemptId: "exec_00000000-0000-4000-8000-000000000001",
    });
    expect(JSON.parse(output()).detached).toBe(true);
    expect(resumeRecordedAgent).not.toHaveBeenCalled();
  });

  it("errors for an unknown run before launching anything", async () => {
    store.get.mockResolvedValue(null);

    await expect(
      runAgentRunsCommand(["resume", "run-404", "--detach"]),
    ).rejects.toThrow("Run not found: run-404");
    expect(launchLocalWorker).not.toHaveBeenCalled();
    expect(workerRequest).not.toHaveBeenCalled();
  });
});

describe("detach argument validation", () => {
  it.each([
    [["list", "--detach"]],
    [["show", "run-1", "--detach"]],
    [["pause", "run-1", "--detach"]],
    [["stop", "run-1", "--detach"]],
    [["approve", "run-1", "--approval", "ap-1", "--detach"]],
    [["list", "--run", "run-1"]],
    [["show", "run-1", "--run", "run-1"]],
  ])("rejects %j without opening the store", async (args) => {
    await expect(runAgentRunsCommand(args)).rejects.toThrow(
      /Invalid agent-runs arguments/,
    );
    expect(openSqliteRunStore).not.toHaveBeenCalled();
  });
});

describe("detach database path resolution", () => {
  const SPEC = {
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_path",
    model: "claude-sonnet-4-6",
    prompt: "test the target",
    target: "https://example.com",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: "/tmp/target" },
    scope: { version: 1, strictScope: true },
  };

  it("defaults to ~/.pensar/runtime/runs.sqlite exactly like the store", async () => {
    vi.stubEnv("PENSAR_DATA_DIR", undefined);
    const previousHome = process.env.HOME;
    try {
      process.env.HOME = "/home/tester";
      store.get.mockResolvedValue({
        runId: "run_path",
        attemptId: "exec_00000000-0000-4000-8000-000000000001",
      });
      launchLocalWorker.mockResolvedValue({
        socketPath: "/tmp/w/run_path.sock",
        logPath: "/tmp/w/run_path.log",
      });
      resolveWorkerExecutable.mockReturnValue({ command: "pensar" });
      workerRequest.mockResolvedValue({ phase: "executing" });

      await runAgentRunsCommand(["resume", "run_path", "--detach"]);

      expect(launchLocalWorker).toHaveBeenCalledWith(
        expect.objectContaining({
          databasePath: "/home/tester/.pensar/runtime/runs.sqlite",
        }),
      );
    } finally {
      process.env.HOME = previousHome;
    }
  });

  it("uses PENSAR_DATA_DIR for both the client and detached worker", async () => {
    vi.stubEnv("PENSAR_DATA_DIR", "/tmp/apex-custom-data");
    launchLocalWorker.mockResolvedValue({
      socketPath: "/tmp/w/run_path.sock",
      logPath: "/tmp/w/run_path.log",
    });
    resolveWorkerExecutable.mockReturnValue({ command: "pensar" });
    workerRequest.mockResolvedValue({ phase: "executing" });

    await runAgentRunsCommand(["start", "--spec", specFile(SPEC), "--detach"]);

    expect(openSqliteRunStore).toHaveBeenCalledWith(undefined);
    expect(launchLocalWorker).toHaveBeenCalledWith(
      expect.objectContaining({
        databasePath: "/tmp/apex-custom-data/runtime/runs.sqlite",
      }),
    );
  });

  it("resolves a relative --store for the worker instead of rejecting it", async () => {
    launchLocalWorker.mockResolvedValue({
      socketPath: "/tmp/w/run_path.sock",
      logPath: "/tmp/w/run_path.log",
    });
    resolveWorkerExecutable.mockReturnValue({ command: "pensar" });
    workerRequest.mockResolvedValue({ phase: "executing" });

    await runAgentRunsCommand([
      "start",
      "--spec",
      specFile(SPEC),
      "--detach",
      "--store",
      "runs/nested.sqlite",
    ]);

    expect(launchLocalWorker).toHaveBeenCalledWith(
      expect.objectContaining({
        databasePath: expect.stringMatching(/runs\/nested\.sqlite$/),
      }),
    );
    const databasePath = launchLocalWorker.mock.calls[0][0].databasePath;
    expect(databasePath.startsWith("/")).toBe(true);
  });
});

describe("detach transport failure guidance", () => {
  const SPEC = {
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_unc",
    model: "claude-sonnet-4-6",
    prompt: "test the target",
    target: "https://example.com",
    activeTools: ["read_file"],
    environment: { kind: "local", cwd: "/tmp/target" },
    scope: { version: 1, strictScope: true },
  };

  it("tells the user to inspect the run on an uncertain transport failure", async () => {
    const { LocalWorkerTransportError } = await import(
      "../core/runtime/localWorkerTransport"
    );
    launchLocalWorker.mockResolvedValue({
      socketPath: "/tmp/w/run_unc.sock",
      logPath: "/tmp/w/run_unc.log",
    });
    workerRequest.mockRejectedValue(
      new LocalWorkerTransportError("connection lost mid-request", {
        uncertain: true,
      }),
    );
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      await expect(
        runAgentRunsCommand(["start", "--spec", specFile(SPEC), "--detach"]),
      ).rejects.toThrow("connection lost mid-request");

      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining("uncertain and was NOT retried"),
      );
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining("agent-runs show run_unc"),
      );
      expect(workerRequest).toHaveBeenCalledTimes(1);
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe("worker store validation", () => {
  it.each([
    "--detach",
    "--context",
    "--spec=spec.json",
  ])("rejects unrelated worker option %s", async (option) => {
    await expect(
      runAgentRunsCommand([
        "worker",
        "--run",
        "run-1",
        "--store",
        "/tmp/runs.sqlite",
        option,
      ]),
    ).rejects.toThrow(/agent-runs worker requires/);
    expect(serveLocalRunWorker).not.toHaveBeenCalled();
  });

  it("rejects a non-absolute --store before invoking the worker", async () => {
    await expect(
      runAgentRunsCommand([
        "worker",
        "--run",
        "run-1",
        "--store",
        "runs.sqlite",
      ]),
    ).rejects.toThrow(/absolute database/);
    expect(serveLocalRunWorker).not.toHaveBeenCalled();
  });
});
