import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runRecordedAgent = vi.hoisted(() => vi.fn());
const inspectSessionEvidence = vi.hoisted(() => vi.fn());
const openSqliteRunStore = vi.hoisted(() => vi.fn());
const configGet = vi.hoisted(() => vi.fn());
const buildAuthConfig = vi.hoisted(() => vi.fn());

vi.mock("../core/api", () => ({ runRecordedAgent, inspectSessionEvidence }));
vi.mock("../core/runtime/sqliteRunStore", () => ({ openSqliteRunStore }));
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

function addedSince(
  current: ReturnType<typeof process.listeners>,
  before: ReturnType<typeof process.listeners>,
) {
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
