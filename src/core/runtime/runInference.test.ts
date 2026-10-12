import { describe, expect, it } from "vitest";
import type { InferenceAttempt } from "../ai";
import {
  RUN_PERSISTENCE_FAILED_MESSAGE,
  RunPersistenceError,
} from "./persistenceError";
import { createRunInferenceRecorder } from "./runInference";
import { RunLimitError, type RunModelStore } from "./runModelStore";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeAttempt(
  overrides: Partial<InferenceAttempt> = {},
): InferenceAttempt {
  return {
    schema: "pensar.inference_attempt",
    version: 1,
    attemptId: "atm_1",
    idempotencyKey: "idem_1",
    lifecycle: "started",
    operationKind: "agent.stream",
    lineage: { sequence: 1 },
    attribution: { rootAttemptId: "atm_1" },
    requested: { provider: "anthropic", modelId: "claude-sonnet-4-5" },
    effective: { provider: "anthropic", modelId: "claude-sonnet-4-5" },
    tokens: {
      inclusiveInput: null,
      uncachedInput: 10,
      cacheRead: null,
      cacheWrite: null,
      output: 5,
    },
    evidence: {},
    ...overrides,
  } as InferenceAttempt;
}

type Gate = {
  promise: Promise<void>;
  release: () => void;
  consumed?: boolean;
};

function gated(): Gate {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

type StoreLog = {
  method: string;
  args: unknown[];
};

function makeStore(script?: {
  fail?: { method: string; on?: number };
  limitOn?: string;
  gates?: Array<{ method: string; gate: Gate }>;
}) {
  const log: StoreLog[] = [];
  const counts = new Map<string, number>();
  const record = (method: string, args: unknown[]) => {
    log.push({ method, args });
    counts.set(method, (counts.get(method) ?? 0) + 1);
  };
  const store = {
    async startModelAttempt(
      runId: string,
      executionAttemptId: string,
      attempt: unknown,
    ) {
      record("startModelAttempt", [runId, executionAttemptId, attempt]);
      await maybeGate("startModelAttempt");
      if (script?.limitOn === "startModelAttempt") {
        throw new RunLimitError("attempt limit reached");
      }
      maybeFail("startModelAttempt");
    },
    async observeModelToolCall(
      runId: string,
      executionAttemptId: string,
      attemptId: string,
      call: unknown,
    ) {
      record("observeModelToolCall", [
        runId,
        executionAttemptId,
        attemptId,
        call,
      ]);
      await maybeGate("observeModelToolCall");
      maybeFail("observeModelToolCall");
    },
    async settleModelAttempt(
      runId: string,
      executionAttemptId: string,
      attempt: unknown,
    ) {
      record("settleModelAttempt", [runId, executionAttemptId, attempt]);
      await maybeGate("settleModelAttempt");
      maybeFail("settleModelAttempt");
    },
    async recordRetry(
      runId: string,
      executionAttemptId: string,
      decision: unknown,
    ) {
      record("recordRetry", [runId, executionAttemptId, decision]);
      maybeFail("recordRetry");
    },
    async listModelAttempts() {
      return [];
    },
    async listRetries() {
      return [];
    },
  } as unknown as RunModelStore;
  function maybeFail(method: string) {
    const fail = script?.fail;
    if (fail && fail.method === method) {
      const on = fail.on ?? 1;
      if ((counts.get(method) ?? 0) === on) throw new Error("disk on fire");
    }
  }
  async function maybeGate(method: string) {
    const entry = script?.gates?.find(
      (g) => g.method === method && !g.gate.consumed,
    );
    if (entry) {
      entry.gate.consumed = true;
      await entry.gate.promise;
    }
  }
  return { store, log };
}

function recorder(store: RunModelStore) {
  return createRunInferenceRecorder({
    runId: "run_1",
    executionAttemptId: "exec_1",
    store,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createRunInferenceRecorder", () => {
  it("awaits each store write before resolving; ids pass through unchanged", async () => {
    const { store, log } = makeStore();
    const r = recorder(store);
    const attempt = makeAttempt();
    await r.beforeDispatch(attempt);
    await r.beforeToolCall("atm_1", {
      toolCallId: "tc_1",
      toolName: "read_file",
    });
    r.settle(makeAttempt({ lifecycle: "completed" }));
    await r.retry({
      authority: "stream-rate-limit",
      count: 1,
      maxRetries: 5,
      delayMs: 1000,
    });
    await r.flush();

    expect(log.map((e) => e.method)).toEqual([
      "startModelAttempt",
      "observeModelToolCall",
      "settleModelAttempt",
      "recordRetry",
    ]);
    for (const entry of log) {
      expect(entry.args[0]).toBe("run_1");
      expect(entry.args[1]).toBe("exec_1");
    }
    expect(r.runId).toBe("run_1");
  });

  it("serializes writes: a gated earlier write blocks later store calls", async () => {
    const first = gated();
    const second = gated();
    const { store, log } = makeStore({
      gates: [
        { method: "startModelAttempt", gate: first },
        { method: "observeModelToolCall", gate: second },
      ],
    });
    const r = recorder(store);

    const dispatch = r.beforeDispatch(makeAttempt());
    const toolCall = r.beforeToolCall("atm_1", {
      toolCallId: "tc_1",
      toolName: "read_file",
    });

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(log.map((e) => e.method)).toEqual(["startModelAttempt"]);
    first.release();
    await dispatch;
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(log.map((e) => e.method)).toEqual([
      "startModelAttempt",
      "observeModelToolCall",
    ]);
    second.release();
    await toolCall;
  });

  it("pre-dispatch waits for prior pending writes before the store starts", async () => {
    const gate = gated();
    const { store, log } = makeStore({
      gates: [{ method: "observeModelToolCall", gate }],
    });
    const r = recorder(store);

    const toolCall = r.beforeToolCall("atm_1", {
      toolCallId: "tc_1",
      toolName: "read_file",
    });
    const dispatch = r.beforeDispatch(makeAttempt());

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(log.map((e) => e.method)).toEqual(["observeModelToolCall"]);
    gate.release();
    await Promise.all([toolCall, dispatch]);
    expect(log.map((e) => e.method)).toEqual([
      "observeModelToolCall",
      "startModelAttempt",
    ]);
  });

  it("a failed terminal settlement surfaces through flush and blocks dispatch", async () => {
    const { store, log } = makeStore({
      fail: { method: "settleModelAttempt", on: 1 },
    });
    const r = recorder(store);

    // Terminal callbacks discard settlement errors — settle is sync void.
    expect(() => r.settle(makeAttempt({ lifecycle: "failed" }))).not.toThrow();
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);

    // No dispatch after a failed settlement.
    await expect(r.beforeDispatch(makeAttempt())).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    await expect(
      r.beforeToolCall("atm_1", { toolCallId: "tc_1", toolName: "x" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(
      r.retry({
        authority: "context-restart",
        count: 1,
        maxRetries: 5,
        delayMs: 0,
      }),
    ).rejects.toBeInstanceOf(RunPersistenceError);

    expect(log.map((e) => e.method)).toEqual(["settleModelAttempt"]);
  });

  it("RunLimitError is preserved, not relabeled as persistence", async () => {
    const { store, log } = makeStore({ limitOn: "startModelAttempt" });
    const r = recorder(store);

    await expect(r.beforeDispatch(makeAttempt())).rejects.toBeInstanceOf(
      RunLimitError,
    );
    await expect(r.beforeDispatch(makeAttempt())).rejects.toBeInstanceOf(
      RunLimitError,
    );
    await expect(r.flush()).rejects.toMatchObject({ name: "RunLimitError" });
    expect(log).toHaveLength(1); // latched: no second store call
  });

  it("other store errors are wrapped with the constant persistence message", async () => {
    const { store } = makeStore({
      fail: { method: "startModelAttempt", on: 1 },
    });
    const r = recorder(store);

    const failure = r.beforeDispatch(makeAttempt());
    await expect(failure).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(failure).rejects.toMatchObject({
      message: RUN_PERSISTENCE_FAILED_MESSAGE,
      cause: expect.objectContaining({ message: "disk on fire" }),
    });
  });

  it("inputs are detached: caller mutation after the call cannot reach the store", async () => {
    const { store, log } = makeStore();
    const r = recorder(store);

    const attempt = makeAttempt();
    const pending = r.beforeDispatch(attempt);
    attempt.tokens.output = 999;
    attempt.lifecycle = "completed";

    const call = { toolCallId: "tc_1", toolName: "read_file" };
    const toolPending = r.beforeToolCall("atm_1", call);
    call.toolName = "mutated";

    await Promise.all([pending, toolPending]);
    const start = log.find((e) => e.method === "startModelAttempt");
    expect(start?.args[2]).toMatchObject({
      lifecycle: "started",
      tokens: { output: 5 },
    });
    const observed = log.find((e) => e.method === "observeModelToolCall");
    expect(observed?.args[3]).toEqual({
      toolCallId: "tc_1",
      toolName: "read_file",
    });
  });

  it("uncloneable envelopes latch without a store write and reject, not throw", async () => {
    const { store, log } = makeStore();
    const r = recorder(store);
    const poisonous = {
      ...makeAttempt(),
      get evidence() {
        throw new Error("uncloneable");
      },
    } as unknown as InferenceAttempt;

    // Promise-returning methods reject even on clone failure.
    await expect(r.beforeDispatch(poisonous)).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    expect(log).toHaveLength(0);
    await expect(
      r.beforeToolCall("atm_1", { toolCallId: "tc_1", toolName: "x" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(log).toHaveLength(0);

    // Sync settle latches on clone failure too, without throwing.
    expect(() => r.settle(poisonous)).not.toThrow();
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
    expect(log).toHaveLength(0);
  });

  it("unknown usage fields pass through the recorder unmodified", async () => {
    const { store, log } = makeStore();
    const r = recorder(store);
    // Nulls are "provider did not report" — never coerced or dropped.
    const attempt = makeAttempt({
      tokens: {
        inclusiveInput: null,
        uncachedInput: null,
        cacheRead: null,
        cacheWrite: null,
        output: null,
      },
      evidence: {
        providerRequestId: "req_9",
        cacheBreakpoint: "anthropic.cacheControl",
      },
    });
    await r.beforeDispatch(attempt);
    r.settle(
      makeAttempt({
        attemptId: attempt.attemptId,
        lifecycle: "partial",
        tokens: attempt.tokens,
      }),
    );
    await r.flush();

    const start = log.find((e) => e.method === "startModelAttempt");
    expect(start?.args[2]).toEqual(attempt);
    const settle = log.find((e) => e.method === "settleModelAttempt");
    expect(settle?.args[2]).toMatchObject({
      lifecycle: "partial",
      tokens: attempt.tokens,
    });
  });

  it("flush drains to stability while new writes arrive mid-drain", async () => {
    const gate = gated();
    const { store, log } = makeStore({
      gates: [{ method: "settleModelAttempt", gate }],
    });
    const r = recorder(store);
    await r.beforeDispatch(makeAttempt());

    r.settle(makeAttempt({ lifecycle: "completed" }));
    const flushing = r.flush();
    // A retry decision enqueued while flush is draining must be awaited too.
    const retryCall = r.retry({
      authority: "stream-idle",
      count: 1,
      maxRetries: 3,
      delayMs: 500,
    });
    gate.release();
    await Promise.all([flushing, retryCall]);
    expect(log.map((e) => e.method)).toEqual([
      "startModelAttempt",
      "settleModelAttempt",
      "recordRetry",
    ]);
  });
});
