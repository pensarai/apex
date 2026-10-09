import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const openRecordedRunClient = vi.hoisted(() => vi.fn());
const clientMethods = vi.hoisted(() => ({
  list: vi.fn(),
  observe: vi.fn(),
  watch: vi.fn(),
  start: vi.fn(),
  resume: vi.fn(),
  requestControl: vi.fn(),
  resolveApproval: vi.fn(),
  close: vi.fn(async () => {}),
}));

vi.mock("../core/runtime/recordedRunClient", () => ({
  openRecordedRunClient: openRecordedRunClient,
}));

vi.mock("../core/runtime/sqliteRunStore", () => ({
  openSqliteRunStore: vi.fn(async () => {
    throw new Error("attach must not open the foreground store");
  }),
}));
vi.mock("../core/runtime/launchLocalWorker", () => ({
  launchLocalWorker: vi.fn(),
  resolveWorkerExecutable: vi.fn(),
}));
vi.mock("../core/runtime/localWorkerTransport", () => ({
  workerRequest: vi.fn(),
  LocalWorkerTransportError: class extends Error {},
}));
vi.mock("../core/config", () => ({ config: { get: vi.fn() } }));
vi.mock("../core/ai", () => ({ buildAuthConfig: vi.fn() }));
vi.mock("../core/api", () => ({
  inspectSessionEvidence: vi.fn(),
  resumeRecordedAgent: vi.fn(),
  runRecordedAgent: vi.fn(),
  serveLocalRunWorker: vi.fn(),
  RunRecoveryBlockedError: class extends Error {},
}));

const { runAgentRunsCommand } = await import("./agent-runs");

type View = Record<string, unknown>;

function view(overrides: View = {}): View {
  return {
    runId: "run_attach",
    observation: {
      record: { runId: "run_attach", status: "running" },
      context: null,
      control: null,
      approvals: [],
    },
    worker: null,
    connection: "connected",
    ...overrides,
  };
}

function makeClient() {
  const client = {
    databasePath: "/tmp/fixture-runs.sqlite",
    ...clientMethods,
  };
  openRecordedRunClient.mockResolvedValue(client);
  return client;
}

/** A watch generator that yields views and stops on abort. */
function watchSequence(views: View[]) {
  return async function* (
    _runId: string,
    signal: AbortSignal,
  ): AsyncGenerator<View> {
    for (const item of views) {
      if (signal.aborted) return;
      yield item;
      if (signal.aborted) return;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          signal.removeEventListener("abort", onAbort);
          resolve();
        }, 100);
        const onAbort = () => {
          clearTimeout(timer);
          signal.removeEventListener("abort", onAbort);
          resolve();
        };
        signal.addEventListener("abort", onAbort, { once: true });
      });
    }
  };
}

let logs: string[];
let logSpy: ReturnType<typeof vi.spyOn>;
let drainPending = false;

/** Own-accessor override; deleting it restores the prototype getter. */
function mockNeedDrain(): void {
  Object.defineProperty(process.stdout, "writableNeedDrain", {
    configurable: true,
    get: () => drainPending,
  });
}

function restoreNeedDrain(): void {
  delete (process.stdout as { writableNeedDrain?: boolean }).writableNeedDrain;
}

beforeEach(() => {
  vi.clearAllMocks();
  clientMethods.close.mockReset();
  clientMethods.close.mockResolvedValue(undefined);
  openRecordedRunClient.mockReset();
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  logs = [];
  logSpy.mockImplementation((line: unknown) => {
    logs.push(String(line));
  });
});

afterEach(() => {
  logSpy.mockRestore();
  restoreNeedDrain();
  drainPending = false;
});

describe("agent-runs attach", () => {
  it("--once prints a single observation and closes the client", async () => {
    makeClient();
    clientMethods.observe.mockResolvedValue(
      view({ connection: "offline", worker: null }),
    );

    await runAgentRunsCommand(["attach", "run_attach", "--once"]);

    expect(openRecordedRunClient).toHaveBeenCalledWith(undefined);
    expect(clientMethods.observe).toHaveBeenCalledTimes(1);
    expect(clientMethods.watch).not.toHaveBeenCalled();
    const printed = JSON.parse(logs.join(""));
    expect(printed.connection).toBe("offline");
    expect(printed.runId).toBe("run_attach");
    expect(clientMethods.close).toHaveBeenCalledTimes(1);
    // Detaching never stops the run through the client.
    expect(clientMethods.requestControl).not.toHaveBeenCalled();
    expect(clientMethods.start).not.toHaveBeenCalled();
    expect(clientMethods.resume).not.toHaveBeenCalled();
  });

  it("--once forwards --store to the client", async () => {
    makeClient();
    clientMethods.observe.mockResolvedValue(view());

    await runAgentRunsCommand([
      "attach",
      "run_attach",
      "--once",
      "--store",
      "/tmp/other.sqlite",
    ]);

    expect(openRecordedRunClient).toHaveBeenCalledWith("/tmp/other.sqlite");
  });

  it("follow consumes generator updates as one JSON line per view", async () => {
    makeClient();
    clientMethods.watch.mockImplementation(
      watchSequence([
        view({ observation: { record: { status: "admitted" } } }),
        view({ observation: { record: { status: "running" } } }),
        view({ observation: { record: { status: "completed" } } }),
      ]),
    );

    await runAgentRunsCommand(["attach", "run_attach"]);

    const statuses = logs.map(
      (line) => JSON.parse(line).observation.record.status,
    );
    expect(statuses).toEqual(["admitted", "running", "completed"]);
    expect(clientMethods.close).toHaveBeenCalledTimes(1);
  });

  it("SIGINT detaches observation without stopping the run", async () => {
    makeClient();
    clientMethods.watch.mockImplementation(
      watchSequence([view(), view(), view(), view(), view()]),
    );
    const before = {
      sigint: process.listenerCount("SIGINT"),
      sigterm: process.listenerCount("SIGTERM"),
    };

    const running = runAgentRunsCommand(["attach", "run_attach"]);
    await vi.waitFor(() =>
      expect(clientMethods.watch).toHaveBeenCalledTimes(1),
    );
    process.emit("SIGINT");
    await running;

    // The generator observed the abort and the loop ended cleanly.
    const printed = logs.map((line) => JSON.parse(line).runId);
    expect(printed.length).toBeLessThanOrEqual(5);
    expect(printed.every((id: string) => id === "run_attach")).toBe(true);
    expect(clientMethods.close).toHaveBeenCalledTimes(1);
    expect(clientMethods.requestControl).not.toHaveBeenCalled();
    expect(process.listenerCount("SIGINT")).toBe(before.sigint);
    expect(process.listenerCount("SIGTERM")).toBe(before.sigterm);
  });

  it("SIGTERM detaches like Ctrl-C", async () => {
    makeClient();
    clientMethods.watch.mockImplementation(
      watchSequence([view(), view(), view()]),
    );

    const running = runAgentRunsCommand(["attach", "run_attach"]);
    await vi.waitFor(() =>
      expect(clientMethods.watch).toHaveBeenCalledTimes(1),
    );
    process.emit("SIGTERM");
    await running;

    expect(clientMethods.close).toHaveBeenCalledTimes(1);
    expect(clientMethods.requestControl).not.toHaveBeenCalled();
  });

  it("an observation failure rethrows after cleaning up listeners and closing", async () => {
    makeClient();
    clientMethods.watch.mockImplementation(async function* () {
      yield view();
      throw new Error("worker endpoint vanished");
    });
    const before = {
      sigint: process.listenerCount("SIGINT"),
      sigterm: process.listenerCount("SIGTERM"),
    };

    await expect(runAgentRunsCommand(["attach", "run_attach"])).rejects.toThrow(
      "worker endpoint vanished",
    );

    expect(clientMethods.close).toHaveBeenCalledTimes(1);
    expect(process.listenerCount("SIGINT")).toBe(before.sigint);
    expect(process.listenerCount("SIGTERM")).toBe(before.sigterm);
  });

  it("an abort-time failure from the client surfaces as a clean detach", async () => {
    makeClient();
    clientMethods.watch.mockImplementation(async function* (
      _runId: string,
      signal: AbortSignal,
    ): AsyncGenerator<View> {
      await new Promise<void>((resolve) => {
        signal.addEventListener("abort", () => resolve(), { once: true });
      });
      throw new Error("watch aborted");
    });

    const running = runAgentRunsCommand(["attach", "run_attach"]);
    await vi.waitFor(() =>
      expect(clientMethods.watch).toHaveBeenCalledTimes(1),
    );
    process.emit("SIGINT");
    // The CLI's signal is aborted, so the client's abort-time rejection is
    // a detach, not a failure.
    await expect(running).resolves.toBeUndefined();
    expect(clientMethods.close).toHaveBeenCalledTimes(1);
  });

  it("a slow stdout holds the next view until drain completes", async () => {
    makeClient();
    drainPending = true;
    mockNeedDrain();
    let pulls = 0;
    clientMethods.watch.mockImplementation(async function* (
      _runId: string,
      signal: AbortSignal,
    ): AsyncGenerator<View> {
      for (const item of [
        view({ worker: { sequence: 1 } }),
        view({ worker: { sequence: 2 } }),
      ]) {
        if (signal.aborted) return;
        pulls += 1;
        yield item;
      }
    });
    const drainBaseline = process.stdout.listenerCount("drain");

    const running = runAgentRunsCommand(["attach", "run_attach"]);
    await vi.waitFor(() => expect(logs.length).toBe(1));
    // Drain pending: no second generator pull happens while stdout is slow.
    await new Promise((r) => setTimeout(r, 150));
    expect(pulls).toBe(1);
    expect(logs.length).toBe(1);

    process.stdout.emit("drain");
    drainPending = false;
    await vi.waitFor(() => expect(logs.length).toBe(2));
    // No further drain wait — the loop finishes and closes.
    await running;
    expect(pulls).toBe(2);
    expect(clientMethods.close).toHaveBeenCalledTimes(1);
    expect(process.stdout.listenerCount("drain")).toBe(drainBaseline);
  });

  it("SIGINT during a pending drain cancels the wait without stopping the run", async () => {
    makeClient();
    mockNeedDrain();
    drainPending = true;
    clientMethods.watch.mockImplementation(
      watchSequence([view(), view(), view(), view(), view()]),
    );
    const baseline = {
      drain: process.stdout.listenerCount("drain"),
      sigint: process.listenerCount("SIGINT"),
      sigterm: process.listenerCount("SIGTERM"),
    };

    const running = runAgentRunsCommand(["attach", "run_attach"]);
    await vi.waitFor(() => expect(logs.length).toBe(1));

    process.emit("SIGINT");
    await running;

    // Only the pre-drain view printed; the drain wait was cancelled.
    expect(logs.length).toBe(1);
    expect(clientMethods.close).toHaveBeenCalledTimes(1);
    expect(clientMethods.requestControl).not.toHaveBeenCalled();
    expect(process.stdout.listenerCount("drain")).toBe(baseline.drain);
    expect(process.listenerCount("SIGINT")).toBe(baseline.sigint);
    expect(process.listenerCount("SIGTERM")).toBe(baseline.sigterm);
  });

  it("invalid arguments are rejected without opening a client", async () => {
    openRecordedRunClient.mockReset();

    await expect(runAgentRunsCommand(["attach"])).rejects.toThrow(
      /Invalid agent-runs arguments/,
    );
    await expect(
      runAgentRunsCommand(["attach", "run_x", "extra"]),
    ).rejects.toThrow(/Invalid agent-runs arguments/);
    await expect(
      runAgentRunsCommand(["attach", "run_x", "--spec", "spec.json"]),
    ).rejects.toThrow(/Invalid agent-runs arguments/);
    await expect(runAgentRunsCommand(["list", "--once"])).rejects.toThrow(
      /Invalid agent-runs arguments/,
    );
    await expect(
      runAgentRunsCommand(["show", "run_x", "--once"]),
    ).rejects.toThrow(/Invalid agent-runs arguments/);

    expect(openRecordedRunClient).not.toHaveBeenCalled();
  });
});
