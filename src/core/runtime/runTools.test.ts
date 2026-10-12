import type { ToolResultPart } from "ai";
import { describe, expect, it, vi } from "vitest";
import { RunPersistenceError } from "./persistenceError";
import { RunControlInterruption } from "./runControlStore";
import type {
  RecordedToolInput,
  RecordedToolOperation,
  RunToolStore,
} from "./runToolStore";
import { createRunToolRecorder } from "./runTools";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Gate = { promise: Promise<void>; release: () => void };

function gated(): Gate {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

interface StoreLog {
  method: string;
  args: unknown[];
}

function makeOperation(
  input: RecordedToolInput,
  overrides: Partial<RecordedToolOperation> = {},
): RecordedToolOperation {
  return {
    schemaVersion: 1,
    operationId: `op_${input.toolCallId}`,
    executionAttemptId: "exec_1",
    sequence: 1,
    context: { epoch: 1, revision: 1 },
    state: "started",
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...input,
    ...overrides,
  };
}

function makeStore(script?: {
  duplicate?: RecordedToolOperation;
  fail?: { method: string; on?: number };
  gate?: { method: string; gate: Gate };
}) {
  const log: StoreLog[] = [];
  const counts = new Map<string, number>();
  const tick = (method: string) =>
    counts.set(method, (counts.get(method) ?? 0) + 1);
  const store: RunToolStore = {
    async initializeToolJournal() {},
    async hasToolJournal() {
      return true;
    },
    async startToolOperation(runId, executionAttemptId, input) {
      log.push({
        method: "startToolOperation",
        args: [runId, executionAttemptId, input],
      });
      tick("startToolOperation");
      await maybeGate("startToolOperation");
      maybeFail("startToolOperation");
      if (script?.duplicate)
        return { created: false, operation: script.duplicate };
      return { created: true, operation: makeOperation(input) };
    },
    async settleToolOperation(
      runId,
      executionAttemptId,
      toolCallId,
      output,
      evidence,
    ) {
      log.push({
        method: "settleToolOperation",
        args: [runId, executionAttemptId, toolCallId, output, evidence],
      });
      tick("settleToolOperation");
      await maybeGate("settleToolOperation");
      maybeFail("settleToolOperation");
    },
    async markToolOutcomeUnknown(runId, executionAttemptId, toolCallId) {
      log.push({
        method: "markToolOutcomeUnknown",
        args: [runId, executionAttemptId, toolCallId],
      });
      tick("markToolOutcomeUnknown");
      maybeFail("markToolOutcomeUnknown");
    },
    async listToolOperations() {
      return [];
    },
  };
  function maybeFail(method: string) {
    const fail = script?.fail;
    if (!fail || fail.method !== method) return;
    if ((counts.get(method) ?? 0) === (fail.on ?? 1)) {
      throw new Error("disk on fire");
    }
  }
  async function maybeGate(method: string) {
    const entry = script?.gate;
    if (!entry || entry.method !== method) return;
    await entry.gate.promise;
  }
  return { store, log };
}

function makeRecorder(
  store: RunToolStore,
  collectEvidence = vi.fn(async () => ({ rootPath: "/session", files: [] })),
) {
  return createRunToolRecorder({
    runId: "run_1",
    executionAttemptId: "exec_1",
    store,
    collectEvidence,
  });
}

const call = (toolName: string, toolCallId: string, input: unknown = {}) => ({
  toolCallId,
  toolName,
  input,
});

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

describe("tool policy classification", () => {
  it.each([
    ["read_file", "read_only"],
    ["list_files", "read_only"],
    ["grep", "read_only"],
    ["list_tasks", "read_only"],
    ["http_request", "external_effect"],
    ["execute_command", "shell_state"],
    ["document_vulnerability", "local_mutation"],
    ["write_plan", "local_mutation"],
    ["create_task", "local_mutation"],
    ["update_task", "local_mutation"],
  ] as const)("classifies %s as %s", async (toolName, policy) => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    await r.beforeExecute(call(toolName, "tc_1"));
    const recorded = log[0]?.args[2] as RecordedToolInput;
    expect(recorded.policy).toBe(policy);
    expect(recorded.toolName).toBe(toolName);
  });

  it("unknown tools fail closed without a store write", async () => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    await expect(
      r.beforeExecute(call("spawn_pentest_agent", "tc_1")),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(log).toHaveLength(0);
    // Latched: subsequent calls fail too.
    await expect(
      r.beforeExecute(call("read_file", "tc_2")),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(log).toHaveLength(0);
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it.each([
    "toString",
    "constructor",
    "__proto__",
    "hasOwnProperty",
    "valueOf",
  ])("prototype-chain name %s fails closed before any store write", async (toolName) => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    await expect(
      r.beforeExecute(call(toolName, "tc_1")),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(log).toHaveLength(0);
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });
});

// ---------------------------------------------------------------------------
// Ordering and serialization
// ---------------------------------------------------------------------------

describe("write ordering", () => {
  it("start write settles before beforeExecute resolves", async () => {
    const gate = gated();
    const { store, log } = makeStore({
      gate: { method: "startToolOperation", gate },
    });
    const r = makeRecorder(store);

    let resolved = false;
    const pending = r.beforeExecute(call("read_file", "tc_1")).then(() => {
      resolved = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(resolved).toBe(false); // gate holds the dispatch decision
    expect(log).toHaveLength(1);

    gate.release();
    await pending;
    expect(resolved).toBe(true);
    expect((await pending) as undefined).toBeUndefined();
  });

  it("settle waits for an in-flight start before writing", async () => {
    const gate = gated();
    const { store, log } = makeStore({
      gate: { method: "startToolOperation", gate },
    });
    const r = makeRecorder(store);

    const dispatch = r.beforeExecute(call("read_file", "tc_1"));
    const settle = r.settle("tc_1", { type: "text", value: "done" });

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(log.map((e) => e.method)).toEqual(["startToolOperation"]);
    gate.release();
    await Promise.all([dispatch, settle]);
    expect(log.map((e) => e.method)).toEqual([
      "startToolOperation",
      "settleToolOperation",
    ]);
  });

  it("flush drains queued writes arriving mid-drain", async () => {
    const gate = gated();
    const { store, log } = makeStore({
      gate: { method: "settleToolOperation", gate },
    });
    const r = makeRecorder(store);
    await r.beforeExecute(call("read_file", "tc_1"));

    const settle = r.settle("tc_1", { type: "text", value: "done" });
    const flushing = r.flush();
    const unknown = r.unknown("tc_2"); // enqueued during the drain
    gate.release();
    await Promise.all([settle, flushing, unknown]);

    expect(log.map((e) => e.method)).toEqual([
      "startToolOperation",
      "settleToolOperation",
      "markToolOutcomeUnknown",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Failure latch
// ---------------------------------------------------------------------------

describe("critical failure latch", () => {
  it("first failure latches and blocks later writes even when the SDK swallows the rejection", async () => {
    const { store, log } = makeStore({
      fail: { method: "startToolOperation", on: 1 },
    });
    const r = makeRecorder(store);

    // The SDK discards this rejection — no await, catch only.
    void r.beforeExecute(call("read_file", "tc_1")).catch(() => {});
    await new Promise((resolve) => setTimeout(resolve, 0));

    await expect(r.beforeExecute(call("grep", "tc_2"))).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    await expect(
      r.settle("tc_2", { type: "text", value: "x" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(r.unknown("tc_2")).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);

    expect(log).toHaveLength(1); // only the failed start was attempted
  });

  it("a settle failure latches after the operation executed", async () => {
    const { store, log } = makeStore({
      fail: { method: "settleToolOperation", on: 1 },
    });
    const r = makeRecorder(store);
    await r.beforeExecute(call("http_request", "tc_1"));

    await expect(
      r.settle("tc_1", { type: "text", value: "200 OK" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(r.beforeExecute(call("grep", "tc_2"))).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    expect(log.map((e) => e.method)).toEqual([
      "startToolOperation",
      "settleToolOperation",
    ]);
  });

  it("wraps store errors with the constant message; no raw cause in message", async () => {
    const { store } = makeStore({
      fail: { method: "startToolOperation", on: 1 },
    });
    const r = makeRecorder(store);
    const failure = r.beforeExecute(call("read_file", "tc_1"));
    await expect(failure).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(failure).rejects.toMatchObject({
      message: expect.stringContaining("Run persistence failed"),
      cause: expect.objectContaining({ message: "disk on fire" }),
    });
  });
});

// ---------------------------------------------------------------------------
// Mutation isolation
// ---------------------------------------------------------------------------

describe("input and output isolation", () => {
  it("caller mutation after beforeExecute cannot reach the committed input", async () => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    const input = { command: "ls -la", timeout: 30 };
    const pending = r.beforeExecute(call("execute_command", "tc_1", input));
    input.command = "rm -rf /";
    input.timeout = 0;
    await pending;

    const recorded = log[0]?.args[2] as RecordedToolInput;
    expect(recorded.input).toEqual({ command: "ls -la", timeout: 30 });
  });

  it("reused outputs are detached from the store's copy", async () => {
    const duplicate = makeOperation(
      {
        toolCallId: "tc_1",
        toolName: "read_file",
        input: {},
        policy: "read_only",
      },
      { state: "settled", output: { type: "text", value: "file contents" } },
    );
    const { store } = makeStore({ duplicate });
    const r = makeRecorder(store);

    const first = await r.beforeExecute(call("read_file", "tc_1"));
    if (first.kind !== "reuse") throw new Error("expected reuse");
    // Mutate the reused output; a second reuse must return pristine data.
    (first.output as { value: string }).value = "tampered";

    const second = await r.beforeExecute(call("read_file", "tc_1"));
    expect(second).toEqual({
      kind: "reuse",
      output: { type: "text", value: "file contents" },
    });
    // And the stored copy was never touched.
    expect(duplicate.output).toEqual({ type: "text", value: "file contents" });
  });

  it("settle snapshots the output before enqueueing", async () => {
    const gate = gated();
    const { store, log } = makeStore({
      gate: { method: "settleToolOperation", gate },
    });
    const r = makeRecorder(store);
    await r.beforeExecute(call("grep", "tc_1"));

    const output = { type: "text", value: "match" } as ToolResultPart["output"];
    const settle = r.settle("tc_1", output);
    (output as { value: string }).value = "mutated after call";
    gate.release();
    await settle;

    const written = log.find((e) => e.method === "settleToolOperation")
      ?.args[3] as ToolResultPart["output"];
    expect(written).toMatchObject({ type: "text", value: "match" });
  });
});

// ---------------------------------------------------------------------------
// Duplicate admission
// ---------------------------------------------------------------------------

describe("duplicate tool operations", () => {
  function duplicateOperation(
    overrides: Partial<RecordedToolOperation>,
  ): RecordedToolOperation {
    return makeOperation(
      {
        toolCallId: "tc_1",
        toolName: "read_file",
        input: {},
        policy: "read_only",
      },
      overrides,
    );
  }

  it("a settled duplicate reuses the exact stored output", async () => {
    const { store, log } = makeStore({
      duplicate: duplicateOperation({
        state: "settled",
        output: { type: "text", value: "prior result" },
      }),
    });
    const r = makeRecorder(store);

    const decision = await r.beforeExecute(call("read_file", "tc_1"));
    expect(decision).toEqual({
      kind: "reuse",
      output: { type: "text", value: "prior result" },
    });
    // Reuse made no new write.
    expect(log).toHaveLength(1);
  });

  it("a started duplicate is refused — never blindly re-executed, even read_only", async () => {
    const { store } = makeStore({
      duplicate: duplicateOperation({ state: "started" }),
    });
    const r = makeRecorder(store);

    await expect(
      r.beforeExecute(call("read_file", "tc_1")),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("an outcome_unknown duplicate is refused", async () => {
    const { store } = makeStore({
      duplicate: duplicateOperation({ state: "outcome_unknown" }),
    });
    const r = makeRecorder(store);

    await expect(
      r.beforeExecute(call("http_request", "tc_1")),
    ).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("a settled duplicate for a different input still never re-executes (conflict is the store's to detect)", async () => {
    // The store is the authority for input-conflict detection; this
    // recorder's contract is only that a settled toolCallId is never
    // re-executed and no result is fabricated.
    const { store, log } = makeStore({
      duplicate: duplicateOperation({
        state: "settled",
        output: { type: "text", value: "prior result" },
      }),
    });
    const r = makeRecorder(store);

    const decision = await r.beforeExecute(
      call("read_file", "tc_1", { path: "/other" }),
    );
    expect(decision.kind).toBe("reuse");
    expect(log).toHaveLength(1); // exactly one admission attempt
  });
});

// ---------------------------------------------------------------------------
// Unknown outcomes
// ---------------------------------------------------------------------------

describe("unknown outcomes", () => {
  it("unknown marks the operation and never overwrites a settled result", async () => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    await r.beforeExecute(call("execute_command", "tc_1"));

    await r.unknown("tc_1");
    expect(log.map((e) => e.method)).toEqual([
      "startToolOperation",
      "markToolOutcomeUnknown",
    ]);

    // A settle after unknown still enqueues — the store owns the
    // refusal when a settled row cannot be overwritten; the recorder
    // surfaces that failure rather than deciding semantics.
    const failStore = makeStore({
      fail: { method: "markToolOutcomeUnknown", on: 1 },
    });
    const r2 = makeRecorder(failStore.store);
    await r2.beforeExecute(call("grep", "tc_2"));
    await expect(r2.unknown("tc_2")).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    await expect(r2.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("unserializable output rejects without a store write", async () => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    await r.beforeExecute(call("read_file", "tc_1"));

    const poisonous = {
      type: "text",
      get value() {
        throw new Error("uncloneable");
      },
    } as unknown as ToolResultPart["output"];
    await expect(r.settle("tc_1", poisonous)).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    expect(log.map((e) => e.method)).toEqual(["startToolOperation"]);
  });

  it("unserializable input rejects before dispatch without a store write", async () => {
    const { store, log } = makeStore();
    const r = makeRecorder(store);
    const poisonous = {
      get path() {
        throw new Error("uncloneable");
      },
    };
    await expect(
      r.beforeExecute(call("read_file", "tc_1", poisonous)),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(log).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

describe("evidence collection", () => {
  it("settle collects evidence and commits it with the output", async () => {
    const { store, log } = makeStore();
    const files = [
      { path: "messages.json", sha256: "a".repeat(64), bytes: 10 },
    ];
    const r = makeRecorder(
      store,
      vi.fn(async () => ({ rootPath: "/s", files })),
    );
    await r.beforeExecute(call("document_vulnerability", "tc_1"));

    await r.settle("tc_1", { type: "text", value: "documented" });

    const written = log.find((e) => e.method === "settleToolOperation");
    expect(written?.args[4]).toEqual({ rootPath: "/s", files });
    expect(written?.args[3]).toEqual({ type: "text", value: "documented" });
  });

  it("evidence collection failure latches", async () => {
    const { store } = makeStore();
    const r = makeRecorder(
      store,
      vi.fn(async () => {
        throw new Error("evidence unavailable");
      }),
    );
    await r.beforeExecute(call("write_plan", "tc_1"));

    const failure = r.settle("tc_1", { type: "text", value: "plan" });
    await expect(failure).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(failure).rejects.toMatchObject({
      cause: expect.objectContaining({ message: "evidence unavailable" }),
    });
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });
});

describe("control interruption fencing", () => {
  function gatedRecorder(
    store: RunToolStore,
    beforeTool: NonNullable<
      Parameters<typeof createRunToolRecorder>[0]["beforeTool"]
    >,
  ) {
    return createRunToolRecorder({
      runId: "run_1",
      executionAttemptId: "exec_1",
      store,
      collectEvidence: async () => ({ rootPath: "/session", files: [] }),
      beforeTool,
    });
  }

  const pausingGate = (pauseAfter: number) => {
    let gateChecks = 0;
    return async () => {
      gateChecks++;
      if (gateChecks > pauseAfter)
        throw new RunControlInterruption("Run paused");
      return undefined;
    };
  };

  it("an accepted sibling still settles after an interruption fences fresh dispatch", async () => {
    const { store, log } = makeStore();
    const r = gatedRecorder(store, pausingGate(1));

    // Sibling A is accepted and executing when a later gate check pauses.
    await expect(r.beforeExecute(call("grep", "tc_a"))).resolves.toEqual({
      kind: "execute",
    });
    await expect(r.beforeExecute(call("grep", "tc_b"))).rejects.toBeInstanceOf(
      RunControlInterruption,
    );

    // Accepted work commits its outcome; the journal is not stranded.
    await r.settle("tc_a", { type: "text", value: "done" });
    expect(log.map((e) => e.method)).toEqual([
      "startToolOperation",
      "settleToolOperation",
    ]);

    // Fresh dispatch stays fenced; flush still surfaces the interruption.
    await expect(
      r.beforeExecute(call("read_file", "tc_c")),
    ).rejects.toBeInstanceOf(RunControlInterruption);
    await expect(r.flush()).rejects.toBeInstanceOf(RunControlInterruption);
  });

  it("unknown for accepted work still commits after an interruption", async () => {
    const { store, log } = makeStore();
    const r = gatedRecorder(store, pausingGate(1));

    await r.beforeExecute(call("execute_command", "tc_a"));
    await expect(
      r.beforeExecute(call("http_request", "tc_b")),
    ).rejects.toBeInstanceOf(RunControlInterruption);

    await r.unknown("tc_a");
    expect(log.map((e) => e.method)).toEqual([
      "startToolOperation",
      "markToolOutcomeUnknown",
    ]);
  });

  it("a start queued behind awaited gate work cannot slip through after the pause", async () => {
    const { store, log } = makeStore();
    const gate = gated();
    let slowReachedGate!: () => void;
    const slowReachedGatePromise = new Promise<void>((resolve) => {
      slowReachedGate = resolve;
    });
    const r = gatedRecorder(store, async (input) => {
      if (input.toolCallId === "tc_slow") {
        slowReachedGate();
        await gate.promise;
      }
      if (input.toolCallId === "tc_pause")
        throw new RunControlInterruption("Run paused");
      return undefined;
    });

    const slow = r.beforeExecute(call("grep", "tc_slow"));
    // tc_slow is parked inside the gate; its start write is not yet queued.
    await slowReachedGatePromise;
    await expect(
      r.beforeExecute(call("grep", "tc_pause")),
    ).rejects.toBeInstanceOf(RunControlInterruption);
    gate.release();

    // The pause landed while tc_slow's start write was still queued.
    await expect(slow).rejects.toBeInstanceOf(RunControlInterruption);
    expect(log).toHaveLength(0);
  });

  it("a failed receipt after an interruption fails closed and dominates the flush surface", async () => {
    const { store } = makeStore({
      fail: { method: "settleToolOperation", on: 1 },
    });
    const r = gatedRecorder(store, pausingGate(1));

    await r.beforeExecute(call("grep", "tc_a"));
    await expect(r.beforeExecute(call("grep", "tc_b"))).rejects.toBeInstanceOf(
      RunControlInterruption,
    );

    // The accepted sibling's receipt write fails: persistence dominates.
    await expect(
      r.settle("tc_a", { type: "text", value: "done" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(r.unknown("tc_a")).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(
      r.beforeExecute(call("read_file", "tc_c")),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    // The interruption must not hide the failed receipt in flush.
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });
});
