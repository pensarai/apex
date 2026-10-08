import type { ToolResultPart } from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RunPersistenceError } from "./persistenceError";
import { createRunControl } from "./runControl";
import {
  type RecordedApproval,
  RunControlConflictError,
  RunControlInterruption,
  type RunControlRecord,
  type RunControlStore,
} from "./runControlStore";

// In-memory fake: CAS, stop dominance, and stop-denies-pending, matching
// the sqlite contract's observable semantics.

function fakeStore(overrides: Partial<RunControlStore> = {}) {
  let control: RunControlRecord | undefined;
  const approvals = new Map<string, RecordedApproval>();
  const byToolCallId = new Map<string, string>();
  const commands: Array<{ intent: string; expectedRevision: number }> = [];
  const requests: Array<{ toolCallId: string; toolName: string }> = [];
  let storageFailure: unknown;

  const store: RunControlStore = {
    initializeControl: async () => {},
    getControl: async () => {
      if (storageFailure) throw storageFailure;
      return control ? { ...control } : undefined;
    },
    requestControl: async (_runId, intent, expectedRevision) => {
      if (storageFailure) throw storageFailure;
      if (!control) throw new Error("Control is not initialized for this run");
      commands.push({ intent, expectedRevision });
      if (control.revision !== expectedRevision) {
        throw new RunControlConflictError("Control revision conflict");
      }
      if (control.intent === intent) return { ...control };
      if (control.intent === "stop") {
        throw new Error("Stop dominates; pause cannot clear stop");
      }
      control = {
        ...control,
        intent,
        revision: control.revision + 1,
        updatedAt: new Date().toISOString(),
      };
      if (intent === "stop") {
        for (const approval of approvals.values()) {
          if (approval.state === "pending") {
            approvals.set(approval.approvalId, {
              ...approval,
              state: "denied",
              reason: "run_stopped",
              decidedAt: control.updatedAt,
            });
          }
        }
      }
      return { ...control };
    },
    requestApproval: async (_runId, _attemptId, request) => {
      if (storageFailure) throw storageFailure;
      requests.push({
        toolCallId: request.toolCallId,
        toolName: request.toolName,
      });
      const existingId = byToolCallId.get(request.toolCallId);
      if (existingId) {
        const existing = approvals.get(existingId);
        if (!existing) throw new Error("Approval record is missing");
        if (
          existing.toolName !== request.toolName ||
          JSON.stringify(existing.input) !== JSON.stringify(request.input)
        ) {
          throw new Error(
            "Approval was already requested with different inputs",
          );
        }
        return { ...existing };
      }
      const approval: RecordedApproval = {
        schemaVersion: 1,
        approvalId: crypto.randomUUID(),
        runId: _runId,
        executionAttemptId: _attemptId,
        toolCallId: request.toolCallId,
        toolName: request.toolName,
        input: structuredClone(request.input),
        specDigest: "a".repeat(64),
        context: { epoch: 1, revision: 1 },
        state: "pending",
        createdAt: new Date().toISOString(),
      };
      approvals.set(approval.approvalId, approval);
      byToolCallId.set(approval.toolCallId, approval.approvalId);
      return { ...approval };
    },
    getApproval: async (_runId, approvalId) => {
      if (storageFailure) throw storageFailure;
      const record = approvals.get(approvalId);
      return record ? { ...record } : undefined;
    },
    listApprovals: async () => {
      if (storageFailure) throw storageFailure;
      return [...approvals.values()].map((a) => ({ ...a }));
    },
    resolveApproval: async (_runId, approvalId, decision) => {
      if (storageFailure) throw storageFailure;
      const record = approvals.get(approvalId);
      if (!record) throw new Error("Approval not found");
      if (record.state === "pending") {
        approvals.set(approvalId, {
          ...record,
          state: decision,
          reason: decision === "denied" ? "user_rejected" : undefined,
          decidedAt: new Date().toISOString(),
        });
      } else if (record.state !== decision) {
        throw new Error("Approval was already resolved differently");
      }
      const settled = approvals.get(approvalId);
      if (!settled) throw new Error("Approval not found");
      return { ...settled };
    },
    ...overrides,
  };

  const enroll = (attemptId = "exec_00000000-0000-4000-8000-000000000001") => {
    control = {
      schemaVersion: 1,
      runId: "run_control_test",
      executionAttemptId: attemptId,
      intent: "run",
      revision: 0,
      updatedAt: new Date().toISOString(),
    };
  };
  const setIntent = (intent: RunControlRecord["intent"]) => {
    if (!control) throw new Error("not enrolled");
    control = { ...control, intent, revision: control.revision + 1 };
  };

  return {
    store,
    enroll,
    setIntent,
    commands,
    requests,
    approvals,
    failStorage: (error: unknown) => {
      storageFailure = error;
    },
  };
}

const ATTEMPT = "exec_00000000-0000-4000-8000-000000000001";
const RUN = "run_control_test";

function makeControl(
  store: RunControlStore,
  extra: { abortSignal?: AbortSignal; pollIntervalMs?: number } = {},
) {
  return createRunControl({
    runId: RUN,
    executionAttemptId: ATTEMPT,
    store,
    requiredTools: ["execute_command"],
    pollIntervalMs: extra.pollIntervalMs ?? 10,
    ...(extra.abortSignal ? { abortSignal: extra.abortSignal } : {}),
  });
}

const active: Array<ReturnType<typeof makeControl>> = [];

beforeEach(() => {
  active.length = 0;
});

afterEach(async () => {
  for (const control of active) await control.dispose();
});

function track<T extends ReturnType<typeof makeControl>>(control: T): T {
  active.push(control);
  return control;
}

describe("beforeDispatch", () => {
  it("proceeds on run intent", async () => {
    const { store, enroll } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    await expect(control.beforeDispatch()).resolves.toBeUndefined();
  });

  it("interrupts on pause and latches it for flush even if the SDK swallowed the throw", async () => {
    const { store, enroll, setIntent } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("pause");
    await expect(control.beforeDispatch()).rejects.toThrow(
      RunControlInterruption,
    );
    await expect(control.flush()).rejects.toThrow("Run paused before dispatch");
  });

  it("stop supersedes a latched pause for the flush surface", async () => {
    const { store, enroll, setIntent } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("pause");
    await expect(control.beforeDispatch()).rejects.toThrow("Run paused");
    setIntent("stop");
    await expect(control.beforeDispatch()).rejects.toThrow("Run stopped");
    await expect(control.flush()).rejects.toThrow(
      "Run stopped before dispatch",
    );
  });

  it("interrupts when another execution attempt owns control", async () => {
    const { store, enroll } = fakeStore();
    enroll("exec_00000000-0000-4000-8000-0000000000ff");
    const control = track(makeControl(store));
    await expect(control.beforeDispatch()).rejects.toThrow(
      /owned by another execution attempt/,
    );
  });

  it("awaits a pending upstream stop write before reading control", async () => {
    const { store, enroll } = fakeStore();
    enroll();
    let releasePersist!: () => void;
    const gate = new Promise<void>((resolve) => {
      releasePersist = resolve;
    });
    const upstream = new AbortController();
    const original = store.requestControl.bind(store);
    store.requestControl = async (runId, intent, revision) => {
      await gate;
      return original(runId, intent, revision);
    };
    const control = track(makeControl(store, { abortSignal: upstream.signal }));

    upstream.abort();
    const dispatch = control.beforeDispatch();
    const early = await Promise.race([
      dispatch.then(
        () => "settled",
        () => "settled",
      ),
      new Promise((resolve) => setTimeout(() => resolve("pending"), 25)),
    ]);
    expect(early).toBe("pending"); // gate cannot observe "run" mid-stop-write
    releasePersist();
    await expect(dispatch).rejects.toThrow("Run stopped before dispatch");
  });
});

describe("beforeTool", () => {
  it("returns undefined for non-required tools without persisting an approval", async () => {
    const { store, enroll, requests } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    await expect(
      control.beforeTool({
        toolCallId: "tc_1",
        toolName: "read_file",
        input: {},
      }),
    ).resolves.toBeUndefined();
    expect(requests).toEqual([]);
  });

  it("persists the request with an input snapshot, then proceeds when approved", async () => {
    const { store, enroll, approvals } = fakeStore();
    enroll();
    const control = track(makeControl(store));

    const input = { command: "ls" };
    const pending = control.beforeTool({
      toolCallId: "tc_1",
      toolName: "execute_command",
      input,
    });
    await vi.waitFor(() => expect(approvals.size).toBe(1));
    // Caller mutation after the request cannot change the bound bytes.
    (input as { command: string }).command = "rm -rf /";
    const [approval] = [...approvals.values()];
    // The bound bytes are the validated input itself, never the wrapper.
    expect(approval.input).toEqual({ command: "ls" });
    expect(approval.input).not.toHaveProperty("toolName");

    await store.resolveApproval(RUN, approval.approvalId, "approved");
    await expect(pending).resolves.toBeUndefined();
  });

  it.each([
    "request",
    "poll",
  ] as const)("refuses an approval observed through %s when cancellation is awaiting persistence", async (source) => {
    const { store, enroll } = fakeStore();
    enroll();
    const upstream = new AbortController();
    let releaseStop!: () => void;
    const stopPending = new Promise<void>((resolve) => {
      releaseStop = resolve;
    });
    const requestControl = store.requestControl;
    store.requestControl = async (...args) => {
      await stopPending;
      return requestControl(...args);
    };
    const requestApproval = store.requestApproval;
    store.requestApproval = async (...args) => {
      const requested = await requestApproval(...args);
      const approved = await store.resolveApproval(
        RUN,
        requested.approvalId,
        "approved",
      );
      if (source === "request") upstream.abort();
      return source === "request" ? approved : requested;
    };
    const getApproval = store.getApproval;
    store.getApproval = async (...args) => {
      const approval = await getApproval(...args);
      if (source === "poll") upstream.abort();
      return approval;
    };
    const control = track(
      makeControl(store, {
        abortSignal: upstream.signal,
        pollIntervalMs: 10_000,
      }),
    );
    try {
      await expect(
        control.beforeTool({
          toolCallId: "tc_approved_abort",
          toolName: "execute_command",
          input: { command: "ls" },
        }),
      ).rejects.toThrow("Run stopped before the approval decision");
      // The host signal must block dispatch even before the stop commits.
      expect((await store.getControl(RUN))?.intent).toBe("run");
      expect(control.signal.aborted).toBe(false);
    } finally {
      releaseStop();
    }
    await expect(control.flush()).rejects.toThrow(RunControlInterruption);
    expect((await store.getControl(RUN))?.intent).toBe("stop");
  });

  it("resolves the stable blocked result on denial — no tool intent or effect", async () => {
    const { store, enroll, approvals } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_2",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    await vi.waitFor(() => expect(approvals.size).toBe(1));
    const [approval] = [...approvals.values()];
    await store.resolveApproval(RUN, approval.approvalId, "denied");
    await expect(pending).resolves.toEqual({
      type: "json",
      value: { blocked: true, reason: "Denied by operator" },
    });
  });

  it("pause interrupts the pending wait and the decision stays durable", async () => {
    const { store, enroll, setIntent, approvals } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_3",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    await vi.waitFor(() => expect(approvals.size).toBe(1));
    setIntent("pause");
    await expect(pending).rejects.toThrow("Run paused before dispatch");
    // The request survives for whoever resumes; nothing was fabricated.
    const [approval] = [...approvals.values()];
    expect((await store.getApproval(RUN, approval.approvalId))?.state).toBe(
      "pending",
    );
    await expect(control.flush()).rejects.toThrow("Run paused");
  });

  it("pause at the tool gate interrupts before any approval request", async () => {
    const { store, enroll, setIntent, requests } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("pause");
    await expect(
      control.beforeTool({
        toolCallId: "tc_3b",
        toolName: "execute_command",
        input: { command: "ls" },
      }),
    ).rejects.toThrow("Run paused before dispatch");
    expect(requests).toEqual([]);
  });

  it("a store-asserted interruption in the approval race is retained, not a storage failure", async () => {
    const { store, enroll, setIntent, requests } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    // Root's hardened requestApproval asserts dispatchability inside the
    // txn: a pause landing after the controller's read throws the typed
    // interruption from the store itself.
    const original = store.requestApproval.bind(store);
    store.requestApproval = async (runId, attemptId, request) => {
      setIntent("pause");
      await original(runId, attemptId, request);
      throw new RunControlInterruption("Run paused before dispatch");
    };

    const pending = control.beforeTool({
      toolCallId: "tc_race",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    await expect(pending).rejects.toBeInstanceOf(RunControlInterruption);
    await expect(pending).rejects.not.toBeInstanceOf(RunPersistenceError);
    // The request write itself landed; only the assertion interrupted.
    expect(requests).toHaveLength(1);
    // No false storage failure: flush surfaces the retained interruption
    // and the signal was never storage-aborted.
    await expect(control.flush()).rejects.toThrow("Run paused before dispatch");
    expect(control.signal.aborted).toBe(false);
  });

  it("observes stop: the denial lands and the gate interrupts", async () => {
    const { store, enroll, setIntent } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_4",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    setIntent("stop");
    await expect(pending).rejects.toThrow(/Run stopped/);
    await expect(control.flush()).rejects.toThrow(
      "Run stopped before dispatch",
    );
  });

  it("interrupts on stop before any approval request", async () => {
    const { store, enroll, setIntent, requests } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("stop");
    await expect(
      control.beforeTool({
        toolCallId: "tc_5",
        toolName: "execute_command",
        input: {},
      }),
    ).rejects.toThrow("Run stopped before dispatch");
    expect(requests).toEqual([]);
  });
});

describe("stop propagation and upstream abort", () => {
  it("polls a persisted stop into its own signal without writing anything", async () => {
    const { store, enroll, setIntent, commands } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("stop"); // client-side command already persisted
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    expect(commands).toEqual([]); // the poll never writes or transitions
  });

  it("persists stop via CAS before aborting its own signal", async () => {
    const { store, enroll, commands } = fakeStore();
    enroll();
    const upstream = new AbortController();
    const control = track(makeControl(store, { abortSignal: upstream.signal }));

    upstream.abort();
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    expect(commands.at(-1)).toEqual({ intent: "stop", expectedRevision: 0 });
    expect((await store.getControl(RUN))?.intent).toBe("stop");
  });

  it("retries CAS conflicts against the current control (bounded, monotonic)", async () => {
    const { store, enroll, commands } = fakeStore();
    enroll();
    const upstream = new AbortController();
    const original = store.requestControl.bind(store);
    // First attempt hits a stale revision; the retry must re-read.
    store.requestControl = async (runId, intent, revision) => {
      if (commands.length === 0) {
        const current = await store.getControl(runId);
        return original(runId, intent, (current?.revision ?? 0) + 99);
      }
      return original(runId, intent, revision);
    };
    const control = track(makeControl(store, { abortSignal: upstream.signal }));

    upstream.abort();
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    expect(commands.length).toBe(2);
    expect((await store.getControl(RUN))?.intent).toBe("stop");
  });

  it("pins a single write on disk failure and propagates the storage error", async () => {
    const { store, enroll, commands } = fakeStore();
    enroll();
    const upstream = new AbortController();
    store.requestControl = async (_runId, intent, expectedRevision) => {
      commands.push({ intent, expectedRevision });
      throw new Error("disk full");
    };
    const control = track(makeControl(store, { abortSignal: upstream.signal }));

    upstream.abort();
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    // Exactly one write attempt — no eight retries, no convergence error.
    expect(commands).toHaveLength(1);
    await expect(control.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("a stale upstream abort does not stop a newer execution owner", async () => {
    const { store, enroll, commands } = fakeStore();
    enroll("exec_00000000-0000-4000-8000-0000000000ff"); // resumed owner
    const upstream = new AbortController();
    const control = track(makeControl(store, { abortSignal: upstream.signal }));

    upstream.abort();
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    expect(commands).toEqual([]); // no stop persisted against the new owner
    expect((await store.getControl(RUN))?.intent).toBe("run");
  });

  it("a pre-aborted upstream signal persists stop before beforeDispatch observes it", async () => {
    const { store, enroll } = fakeStore();
    enroll();
    const upstream = new AbortController();
    upstream.abort();
    const control = track(makeControl(store, { abortSignal: upstream.signal }));
    await expect(control.beforeDispatch()).rejects.toThrow(
      "Run stopped before dispatch",
    );
    expect((await store.getControl(RUN))?.intent).toBe("stop");
  });
});

describe("storage failures", () => {
  it("latch RunPersistenceError, abort execution, and surface at every later gate", async () => {
    const { store, enroll, failStorage } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    failStorage(new Error("sqlite broken"));
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    await expect(control.beforeDispatch()).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    await expect(control.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("a read failure inside beforeTool latches and aborts", async () => {
    const { store, enroll, failStorage } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_6",
      toolName: "execute_command",
      input: {},
    });
    failStorage(new Error("disk died mid-gate"));
    await expect(pending).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(control.flush()).rejects.toBeInstanceOf(RunPersistenceError);
    expect(control.signal.aborted).toBe(true);
  });

  it("flush does not throw merely because pause intent exists in the store", async () => {
    const { store, enroll, setIntent } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("pause");
    await control.flush(); // writes all landed; pause alone never fails
  });

  it("a storage failure after the pause boundary outranks the pause at flush", async () => {
    const { store, enroll, setIntent, failStorage } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    setIntent("pause");
    await expect(control.beforeDispatch()).rejects.toThrow("Run paused");
    failStorage(new Error("control table unreadable"));
    // The failure must be observed by a gate before flush can rank it.
    await expect(control.beforeDispatch()).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    // The API must never report a clean paused outcome over a disk failure.
    await expect(control.flush()).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(control.flush()).rejects.not.toThrow("Run paused");
  });

  it("poll fails closed when the control record is missing", async () => {
    const { store } = fakeStore(); // never enrolled
    const control = track(makeControl(store));
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    await expect(control.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("poll fails closed when another attempt owns the control", async () => {
    const { store, enroll } = fakeStore();
    enroll("exec_00000000-0000-4000-8000-0000000000ff");
    const control = track(makeControl(store));
    await vi.waitFor(() => expect(control.signal.aborted).toBe(true));
    await expect(control.flush()).rejects.toThrow(
      /owned by another execution attempt/,
    );
  });

  it("preserves the actual persistence error when a stop arrives afterwards", async () => {
    const { store, enroll, failStorage, setIntent } = fakeStore();
    enroll();
    const sentinel = new RunPersistenceError(new Error("disk full"));
    const control = track(makeControl(store));
    failStorage(sentinel);
    setIntent("stop");
    await expect(control.beforeDispatch()).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
    // Even a gate-observed stop cannot mask the retained disk failure.
    await expect(control.flush()).rejects.toBe(sentinel);
  });
});

describe("dispose", () => {
  it("stops polling and detaches the upstream listener", async () => {
    const { store, enroll, commands } = fakeStore();
    enroll();
    const upstream = new AbortController();
    const control = track(makeControl(store, { abortSignal: upstream.signal }));

    await control.dispose();
    upstream.abort(); // after dispose: no stop persist, no internal abort
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(control.signal.aborted).toBe(false);
    expect(commands).toEqual([]);
  });

  it("awaits an ongoing approval wait; dispose does not strand it", async () => {
    const { store, enroll } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_7",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    await vi.waitFor(async () =>
      expect((await store.listApprovals(RUN)).length).toBe(1),
    );
    const listed = await store.listApprovals(RUN);
    const first = listed[0];
    if (!first) throw new Error("approval missing");
    await store.resolveApproval(RUN, first.approvalId, "approved");
    await expect(pending).resolves.toBeUndefined();
    await control.dispose();
  });

  it("ends a still-pending approval wait blocked: no dispatch, no reads after disposal, no latched interruption", async () => {
    const { store: base, enroll } = fakeStore();
    enroll();
    let storeReads = 0;
    const store: RunControlStore = {
      ...base,
      getApproval: async (runId, approvalId) => {
        storeReads++;
        return base.getApproval(runId, approvalId);
      },
      getControl: async (runId) => {
        storeReads++;
        return base.getControl(runId);
      },
    };
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_dispose_pending",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    await vi.waitFor(async () =>
      expect((await base.listApprovals(RUN)).length).toBe(1),
    );

    await control.dispose();
    const readsAtDisposal = storeReads;

    const settled = await Promise.race([
      pending,
      new Promise((resolve) => setTimeout(() => resolve("unresolved"), 250)),
    ]);
    expect(settled).toEqual({
      type: "json",
      value: {
        blocked: true,
        reason: "Run ended before the approval decision",
      },
    });
    // The dangling wait must not keep touching the store after disposal.
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(storeReads).toBe(readsAtDisposal);
    // Disposal itself never latches an interruption for a later flush.
    await expect(control.flush()).resolves.toBeUndefined();
  });

  it("an approval decided after disposal never dispatches the dangling tool", async () => {
    const { store, enroll } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_dispose_late_approval",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    const approval = await vi.waitFor(async () => {
      const listed = await store.listApprovals(RUN);
      if (listed.length === 1 && listed[0]) return listed[0];
      throw new Error("approval not requested yet");
    });

    await control.dispose();
    await store.resolveApproval(RUN, approval.approvalId, "approved");

    const settled = await Promise.race([
      pending,
      new Promise((resolve) => setTimeout(() => resolve("unresolved"), 250)),
    ]);
    expect(settled).toEqual({
      type: "json",
      value: {
        blocked: true,
        reason: "Run ended before the approval decision",
      },
    });
  });

  it("gates refuse work after disposal without store access or latching", async () => {
    const { store: base, enroll, requests } = fakeStore();
    enroll();
    let controlReads = 0;
    const store: RunControlStore = {
      ...base,
      getControl: async (runId) => {
        controlReads++;
        return base.getControl(runId);
      },
    };
    const control = track(makeControl(store));
    await control.dispose();
    const readsAtDisposal = controlReads;

    let dispatchError: unknown;
    const dispatch = await Promise.race([
      control.beforeDispatch().then(
        () => "resolved",
        (error: unknown) => {
          dispatchError = error;
          return "rejected";
        },
      ),
      new Promise((resolve) => setTimeout(() => resolve("hung"), 250)),
    ]);
    expect(dispatch).toBe("rejected");
    expect(dispatchError).toBeInstanceOf(RunControlInterruption);

    const tool = await Promise.race([
      control.beforeTool({
        toolCallId: "tc_dispose_gate",
        toolName: "execute_command",
        input: {},
      }),
      new Promise((resolve) => setTimeout(() => resolve("hung"), 250)),
    ]);
    expect(tool).toEqual({
      type: "json",
      value: {
        blocked: true,
        reason: "Run ended before the approval decision",
      },
    });
    // No approval request or control read happened after disposal.
    expect(requests).toEqual([]);
    expect(controlReads).toBe(readsAtDisposal);
    await expect(control.flush()).resolves.toBeUndefined();
  });
});

describe("disposal during in-flight gate reads", () => {
  // Holds the second getControl call — call #1 is the constructor poll, so
  // the held read is deterministically the gate's own readControl.
  function holdingSecondGetControl(base: RunControlStore) {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let calls = 0;
    let secondPending = false;
    const store: RunControlStore = {
      ...base,
      getControl: async (runId: string) => {
        calls++;
        if (calls === 2) {
          secondPending = true;
          await gate;
        }
        return base.getControl(runId);
      },
    };
    return {
      store,
      releaseSecond: () => release(),
      secondInFlight: () => secondPending,
    };
  }

  it("beforeDispatch refuses dispatch when disposal lands while the control read is pending", async () => {
    const { store: base, enroll } = fakeStore();
    enroll();
    const { store, releaseSecond, secondInFlight } =
      holdingSecondGetControl(base);
    // A long poll interval keeps the constructor poll as call #1.
    const control = track(makeControl(store, { pollIntervalMs: 10_000 }));
    const pending = control.beforeDispatch();
    await vi.waitFor(() => expect(secondInFlight()).toBe(true));

    const disposing = control.dispose();
    releaseSecond();
    await disposing;

    await expect(pending).rejects.toThrow(RunControlInterruption);
    await expect(control.flush()).resolves.toBeUndefined();
  });

  it("beforeTool blocks a non-required tool when disposal lands while the control read is pending", async () => {
    const { store: base, enroll } = fakeStore();
    enroll();
    const { store, releaseSecond, secondInFlight } =
      holdingSecondGetControl(base);
    const control = track(makeControl(store, { pollIntervalMs: 10_000 }));
    const pending = control.beforeTool({
      toolCallId: "tc_race_nonrequired",
      toolName: "read_file",
      input: { path: "notes.txt" },
    });
    await vi.waitFor(() => expect(secondInFlight()).toBe(true));

    const disposing = control.dispose();
    releaseSecond();
    await disposing;

    await expect(pending).resolves.toEqual({
      type: "json",
      value: {
        blocked: true,
        reason: "Run ended before the approval decision",
      },
    });
  });

  it("beforeTool creates no approval when disposal lands while the control read is pending", async () => {
    const { store: base, enroll, requests } = fakeStore();
    enroll();
    const { store, releaseSecond, secondInFlight } =
      holdingSecondGetControl(base);
    const control = track(makeControl(store, { pollIntervalMs: 10_000 }));
    const pending = control.beforeTool({
      toolCallId: "tc_race_required",
      toolName: "execute_command",
      input: { command: "ls" },
    });
    await vi.waitFor(() => expect(secondInFlight()).toBe(true));

    const disposing = control.dispose();
    releaseSecond();
    await disposing;

    const settled = await Promise.race([
      pending,
      new Promise((resolve) => setTimeout(() => resolve("unresolved"), 250)),
    ]);
    expect(settled).toEqual({
      type: "json",
      value: {
        blocked: true,
        reason: "Run ended before the approval decision",
      },
    });
    // The approval must not be created for a run that already ended.
    expect(requests).toEqual([]);
  });
});

describe("blocked result shape", () => {
  it("denial resolves valid ToolResultPart output JSON", async () => {
    const { store, enroll, approvals } = fakeStore();
    enroll();
    const control = track(makeControl(store));
    const pending = control.beforeTool({
      toolCallId: "tc_8",
      toolName: "execute_command",
      input: {},
    });
    await vi.waitFor(() => expect(approvals.size).toBe(1));
    const [approval] = [...approvals.values()];
    await store.resolveApproval(RUN, approval.approvalId, "denied");
    const output = (await pending) as ToolResultPart["output"];
    expect(output).toEqual({
      type: "json",
      value: { blocked: true, reason: "Denied by operator" },
    });
  });
});
