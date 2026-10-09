/**
 * Behavior tests for the inference-recording wiring in runRecordedAgent:
 * ALS recorder availability, settlement gating before terminal status,
 * discarded settlement failures, limit enforcement before provider
 * dispatch, deadline abort/expiry/disposal, and no inference on
 * duplicate admission. Mocked session/agent; real recorder via ALS.
 */
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InferenceAttempt } from "../ai";
import { getInferenceRecorder } from "../ai";
import { newSessionId } from "../id/id";
import { RunPersistenceError } from "../runtime/persistenceError";
import type {
  RunControlRecord,
  RunControlStore,
} from "../runtime/runControlStore";
import { RunLimitError, type RunModelStore } from "../runtime/runModelStore";
import type { RunRecoveryStore } from "../runtime/runRecoveryStore";
import type { RecordedRunSpec, RunRecord } from "../runtime/runStore";
import type {
  RunToolStore,
  ToolExecutionRecorder,
} from "../runtime/runToolStore";

const sessionCreate = vi.hoisted(() => vi.fn());
const runAgent = vi.hoisted(() => vi.fn());
// Provider simulation: pushes only when the recorder's dispatch gate passed.
const providerCalls = vi.hoisted(() => [] as string[]);

vi.mock("../session", () => ({ create: sessionCreate }));
vi.mock("./offesecAgent", () => ({ runOffensiveSecurityAgent: runAgent }));

import { runRecordedAgent } from "./recordedRun";

const RUN_RESULT = { streamResult: {}, session: {} } as never;

function makeAttempt(): InferenceAttempt {
  return {
    schema: "pensar.inference_attempt",
    version: 1,
    attemptId: "atm_1",
    idempotencyKey: "idem_1",
    lifecycle: "started",
    operationKind: "agent.stream",
    lineage: { sequence: 1 },
    attribution: { rootAttemptId: "atm_1" },
    requested: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
    effective: { provider: "anthropic", modelId: "claude-sonnet-5-5" },
    tokens: {
      inclusiveInput: null,
      uncachedInput: 10,
      cacheRead: null,
      cacheWrite: null,
      output: 5,
    },
    evidence: {},
  } as InferenceAttempt;
}

function baseSpec(cwd: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_local_test_01",
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
    ...overrides,
  };
}

type Gate = { promise: Promise<void>; release: () => void };

function gated(): Gate {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

function makeModelStore(script?: {
  limitOnStart?: boolean;
  failSettle?: boolean;
  gateSettle?: Gate;
  onSettleCalled?: () => void;
}) {
  let record: RunRecord | undefined;
  let control: RunControlRecord | undefined;
  const calls: string[] = [];
  const store = {
    acquireExecutionLock: async (runId: string) => ({
      runId,
      release: vi.fn(),
    }),
    enrollRecovery: async () => ({}) as never,
    getRecoveryEnrollment: async () => undefined,
    listRecoveries: async () => [],
    claimRecovery: async () => {
      throw new Error("Unexpected recovery");
    },
    initializeControl: async (runId: string, executionAttemptId: string) => {
      control = {
        schemaVersion: 1,
        runId,
        executionAttemptId,
        intent: "run",
        revision: 0,
        updatedAt: new Date().toISOString(),
      };
    },
    getControl: async () => control,
    requestControl: async (
      _runId: string,
      intent: "pause" | "stop",
      revision: number,
    ) => {
      if (!control || control.revision !== revision)
        throw new Error("Control revision changed");
      control = { ...control, intent, revision: revision + 1 };
      return control;
    },
    requestApproval: async () => {
      throw new Error("Unexpected approval");
    },
    getApproval: async () => undefined,
    listApprovals: async () => [],
    resolveApproval: async () => {
      throw new Error("Unexpected approval");
    },
    initializeToolJournal: async () => {},
    hasToolJournal: async () => true,
    startToolOperation: async () => {
      throw new Error("tool intent write failed");
    },
    settleToolOperation: async () => {},
    markToolOutcomeUnknown: async () => {},
    listToolOperations: async () => [],
    admit: async (spec: RecordedRunSpec) => {
      if (record) return { created: false, record };
      record = {
        schemaVersion: 1,
        spec,
        sessionId: newSessionId(),
        attemptId: `exec_${randomUUID()}`,
        runtimeVersion: "test",
        status: "admitted",
        admittedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      calls.push("admit");
      return { created: true, record };
    },
    get: async () => record,
    list: async () => (record ? [record] : []),
    transition: async (
      _runId: string,
      attemptId: string,
      status: RunRecord["status"],
    ) => {
      if (!record || record.attemptId !== attemptId)
        throw new Error("Wrong attempt");
      record = { ...record, status, updatedAt: new Date().toISOString() };
      calls.push(status);
      return record;
    },
    startModelAttempt: async () => {
      calls.push("startModelAttempt");
      if (script?.limitOnStart)
        throw new RunLimitError("attempt limit reached");
    },
    observeModelToolCall: async () => {
      calls.push("observeModelToolCall");
    },
    settleModelAttempt: async () => {
      calls.push("settleModelAttempt");
      script?.onSettleCalled?.();
      if (script?.gateSettle) await script.gateSettle.promise;
      if (script?.failSettle) throw new Error("settle write failed");
    },
    recordRetry: async () => {
      calls.push("recordRetry");
    },
    listModelAttempts: async () => [],
    listRetries: async () => [],
  };
  return {
    store: store as unknown as RunModelStore &
      RunToolStore &
      RunControlStore &
      RunRecoveryStore,
    calls: () => calls,
    current: () => record,
  };
}

let tempDirs: string[];

function tempCwd(): string {
  const dir = mkdtempSync(join(tmpdir(), "recorded-run-inference-"));
  tempDirs.push(dir);
  return dir;
}

beforeEach(() => {
  sessionCreate.mockReset();
  runAgent.mockReset();
  providerCalls.length = 0;
  sessionCreate.mockImplementation(async (input: { id?: string }) => ({
    id: input.id,
    rootPath: "/fake/session/root",
  }));
  // Default agent: real recorder flow — gate, dispatch, settle, return.
  runAgent.mockImplementation(async () => {
    const recorder = getInferenceRecorder();
    if (!recorder) throw new Error("no recorder in ALS context");
    await recorder.beforeDispatch(makeAttempt());
    providerCalls.push("dispatched");
    recorder.settle({ ...makeAttempt(), lifecycle: "completed" });
    return RUN_RESULT;
  });
  tempDirs = [];
});

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("inference recorder availability", () => {
  it("recorder is available inside the agent, including after nested async awaits", async () => {
    let immediate: ReturnType<typeof getInferenceRecorder>;
    let afterAwait: ReturnType<typeof getInferenceRecorder>;
    let nested: ReturnType<typeof getInferenceRecorder>;
    runAgent.mockImplementationOnce(async (input) => {
      immediate = getInferenceRecorder();
      expect(input.inferenceRecorder).toBe(immediate);
      await Promise.resolve();
      afterAwait = getInferenceRecorder();
      // Nested async auxiliary (summarization-style) must inherit the context.
      await (async () => {
        await Promise.resolve();
        nested = getInferenceRecorder();
      })();
      recorderSettled = true;
      return RUN_RESULT;
    });
    let recorderSettled = false;

    const outcome = await runRecordedAgent({
      spec: baseSpec(tempCwd()),
      store: makeModelStore().store,
    });

    expect(outcome.started).toBe(true);
    expect(recorderSettled).toBe(true);
    expect(immediate).toBeDefined();
    expect(afterAwait).toBe(immediate);
    expect(nested).toBe(immediate);
    expect(immediate?.runId).toBe("run_local_test_01");
    // Context exits with the run — no recorder leaks to later callers.
    expect(getInferenceRecorder()).toBeUndefined();
  });
});

describe("settlement durability gates the terminal status", () => {
  it("a held settlement write prevents the completed transition until released", async () => {
    const gate = gated();
    let settleStarted!: () => void;
    const settleStartedPromise = new Promise<void>((resolve) => {
      settleStarted = resolve;
    });
    const { store, calls, current } = makeModelStore({
      gateSettle: gate,
      onSettleCalled: settleStarted,
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempCwd()),
      store,
    });
    // Wait until the settle write is actually in flight (and held) —
    // never a wall-clock guess.
    await settleStartedPromise;
    expect(current()?.status).toBe("running");
    expect(calls()).not.toContain("completed");

    gate.release();
    const outcome = await outcomePromise;
    expect(outcome.record.status).toBe("completed");
    expect(calls()[calls().length - 1]).toBe("completed");
  });

  it("a discarded settlement failure settles the run as failed, not completed", async () => {
    const { store, current } = makeModelStore({ failSettle: true });
    // The agent's terminal callback discards settle()'s rejection (sync
    // void) and the agent itself returns successfully.
    runAgent.mockImplementationOnce(async () => {
      const recorder = getInferenceRecorder();
      if (!recorder) throw new Error("no recorder");
      recorder.settle({ ...makeAttempt(), lifecycle: "completed" });
      return RUN_RESULT;
    });

    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBeInstanceOf(RunPersistenceError);

    expect(current()?.status).toBe("failed");
  });
});

describe("store limit enforcement blocks the provider", () => {
  it("a rejected start write prevents dispatch and surfaces RunLimitError, settling failed", async () => {
    const { store, calls, current } = makeModelStore({ limitOnStart: true });

    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBeInstanceOf(RunLimitError);

    expect(providerCalls).toEqual([]); // provider never dispatched
    expect(calls()).toContain("startModelAttempt"); // the gate was attempted
    expect(current()?.status).toBe("failed");
  });
});

describe("run deadline", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("an expired deadline cancels without invoking the agent", async () => {
    const { store, current } = makeModelStore();
    const deadlineAt = new Date(Date.now() - 1_000).toISOString();

    const outcome = await runRecordedAgent({
      spec: baseSpec(tempCwd(), {
        limits: { deadlineAt },
      }),
      store,
    });

    expect(outcome.started).toBe(false);
    expect(outcome.result).toBeUndefined();
    expect(runAgent).not.toHaveBeenCalled();
    expect(sessionCreate).not.toHaveBeenCalled();
    expect(current()?.status).toBe("cancelled");
  });

  it("deadline expiry aborts the signal the agent holds, settling cancelled", async () => {
    const { store, current } = makeModelStore();
    const deadlineAt = new Date(Date.now() + 1_000).toISOString();
    let signalHeld!: () => void;
    const held = new Promise<void>((resolve) => {
      signalHeld = resolve;
    });
    runAgent.mockImplementationOnce(
      async (input: { abortSignal?: AbortSignal }) => {
        const signal = input.abortSignal;
        if (!signal) throw new Error("expected an abortSignal");
        signalHeld();
        // If the deadline already fired before we got here, resolve at once —
        // a late listener on an aborted signal would never fire.
        if (signal.aborted) {
          const reason = signal.reason;
          throw reason instanceof Error ? reason : new Error("aborted");
        }
        const reason = await new Promise<unknown>((resolve) => {
          signal.addEventListener("abort", () => resolve(signal.reason), {
            once: true,
          });
        });
        throw reason instanceof Error ? reason : new Error("aborted");
      },
    );

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempCwd(), { limits: { deadlineAt } }),
      store,
    });
    // The agent must hold the signal (listener installed) before time moves.
    await held;
    // Attach the rejection expectation before advancing so the rejection
    // is never momentarily unhandled while timers flush.
    const expectation = expect(outcomePromise).rejects.toMatchObject({
      name: "AbortError",
    });
    await vi.advanceTimersByTimeAsync(1_050);
    await expectation;

    expect(current()?.status).toBe("cancelled");
  });

  it("timer is disposed on the error path: a run that fails early never aborts later", async () => {
    const { store, current } = makeModelStore();
    const deadlineAt = new Date(Date.now() + 10_000).toISOString();
    let heldSignal: AbortSignal | undefined;
    runAgent.mockImplementationOnce(
      async (input: { abortSignal?: AbortSignal }) => {
        heldSignal = input.abortSignal;
        throw new Error("agent exploded before the deadline");
      },
    );

    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd(), { limits: { deadlineAt } }),
        store,
      }),
    ).rejects.toThrow("agent exploded before the deadline");
    expect(current()?.status).toBe("failed");

    // Disposed in the finally — advancing past the deadline must not abort.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(heldSignal?.aborted).toBe(false);
  });

  it("a future deadline never fires after a successful run — timer disposed", async () => {
    const { store, current } = makeModelStore();
    const deadlineAt = new Date(Date.now() + 10_000).toISOString();
    let heldSignal: AbortSignal | undefined;
    runAgent.mockImplementationOnce(
      async (input: { abortSignal?: AbortSignal }) => {
        heldSignal = input.abortSignal;
        return RUN_RESULT;
      },
    );

    const outcome = await runRecordedAgent({
      spec: baseSpec(tempCwd(), { limits: { deadlineAt } }),
      store,
    });
    expect(outcome.record.status).toBe("completed");
    expect(current()?.status).toBe("completed");

    await vi.advanceTimersByTimeAsync(20_000);
    expect(heldSignal?.aborted).toBe(false); // disposed — no post-run abort leak
  });
});

describe("duplicate admission performs no inference", () => {
  it("a second run with the same runId starts no agent and no model writes", async () => {
    const { store, calls } = makeModelStore();
    await runRecordedAgent({ spec: baseSpec(tempCwd()), store });
    const firstStarts = calls().filter((c) => c === "startModelAttempt").length;
    expect(firstStarts).toBe(1);
    const agentCallsAfterFirst = runAgent.mock.calls.length;

    const outcome = await runRecordedAgent({
      spec: baseSpec("/any/cwd"),
      store,
    });

    expect(outcome.started).toBe(false);
    expect(runAgent.mock.calls.length).toBe(agentCallsAfterFirst);
    expect(calls().filter((c) => c === "startModelAttempt").length).toBe(1);
  });
});

describe("critical tool journal gates", () => {
  it("blocks the next provider reservation after a discarded tool error", async () => {
    const { store, calls, current } = makeModelStore();
    runAgent.mockImplementationOnce(
      async ({
        toolExecutionRecorder,
      }: {
        toolExecutionRecorder: ToolExecutionRecorder;
      }) => {
        await toolExecutionRecorder
          .beforeExecute({
            toolCallId: "tc_lost_error",
            toolName: "http_request",
            input: { url: "http://127.0.0.1:8080" },
          })
          .catch(() => {});
        await getInferenceRecorder()!.beforeDispatch(makeAttempt());
        providerCalls.push("must not dispatch");
        return RUN_RESULT;
      },
    );
    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(calls()).not.toContain("startModelAttempt");
    expect(providerCalls).toEqual([]);
    expect(current()?.status).toBe("failed");
  });

  it("cannot report completed when the SDK discarded the final tool error", async () => {
    const { store, current } = makeModelStore();
    runAgent.mockImplementationOnce(
      async ({
        toolExecutionRecorder,
      }: {
        toolExecutionRecorder: ToolExecutionRecorder;
      }) => {
        await toolExecutionRecorder
          .beforeExecute({
            toolCallId: "tc_final_error",
            toolName: "http_request",
            input: { url: "http://127.0.0.1:8080" },
          })
          .catch(() => {});
        return RUN_RESULT;
      },
    );
    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(current()?.status).toBe("failed");
  });
});
