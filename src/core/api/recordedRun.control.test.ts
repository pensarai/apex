/**
 * C2 acceptance for the recorded-run control path through the public API:
 * durable approvals, pause/stop intent, and fail-closed control
 * persistence. Real SQLite store + real controller; session and agent are
 * mocked per the existing recordedRun test patterns — the mocked agent
 * drives the real recorder/control seams (toolExecutionRecorder,
 * contextRecorder, ALS inference recorder) exactly as the wired agent does.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InferenceAttempt } from "../ai";
import { getInferenceRecorder } from "../ai";
import { openSqliteRunStore } from "../runtime/sqliteRunStore";

const sessionCreate = vi.hoisted(() => vi.fn());
const runAgent = vi.hoisted(() => vi.fn());

vi.mock("../session", () => ({ create: sessionCreate }));
vi.mock("./offesecAgent", () => ({ runOffensiveSecurityAgent: runAgent }));

import { runRecordedAgent } from "./recordedRun";

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

const RUN_RESULT = { streamResult: {}, session: {} } as never;
const DENIED_BY_OPERATOR = {
  type: "json",
  value: { blocked: true, reason: "Denied by operator" },
} as const;

let tempDirs: string[] = [];
let store: Store | undefined;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function baseSpec(cwd: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_control_test_01",
    prompt: "Request the target homepage once and summarize the response.",
    target: "http://127.0.0.1:8080",
    model: "claude-sonnet-5-5",
    activeTools: ["execute_command", "read_file"],
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

type AgentInput = {
  toolExecutionRecorder: {
    beforeExecute: (input: {
      toolCallId: string;
      toolName: string;
      input: unknown;
    }) => Promise<{ kind: "execute" } | { kind: "reuse"; output: unknown }>;
    settle: (toolCallId: string, output: unknown) => Promise<void>;
  };
  contextRecorder: {
    checkpoint: (input: {
      messages: unknown[];
      system?: string;
    }) => Promise<void>;
  };
};

/** The wired agent's dispatch order: context, then gated tool intent. */
async function primeContext(input: AgentInput): Promise<void> {
  await input.contextRecorder.checkpoint({
    messages: [{ role: "user", content: "run" }],
    system: "system prompt",
  });
}

beforeEach(() => {
  sessionCreate.mockReset();
  runAgent.mockReset();
  // A real-shaped session root: evidence collection at commit/settle time
  // walks these paths (they may simply not exist yet).
  sessionCreate.mockImplementation(async (input: { id?: string }) => {
    const rootPath = tempDir("control-session-root-");
    return {
      id: input.id,
      rootPath,
      findingsPath: join(rootPath, "findings.json"),
      pocsPath: join(rootPath, "pocs"),
      logsPath: join(rootPath, "logs"),
      config: {},
    };
  });
  runAgent.mockResolvedValue(RUN_RESULT);
  tempDirs = [];
});

afterEach(() => {
  store?.close();
  store = undefined;
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

async function openStore(
  dbPath?: string,
): Promise<{ dbPath: string; store: Store }> {
  const path = dbPath ?? join(tempDir("control-db-"), "runs.sqlite");
  return { dbPath: path, store: await openSqliteRunStore(path) };
}

describe("control enrollment and approval gating", () => {
  it("enrolls control before the agent; a pending approval accepts no tool intent or model dispatch", async () => {
    const { store: shared } = await openStore();
    store = shared;
    const runId = "run_ctrl_pending";
    const gate = gated();
    let approvalId = "";

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      // The executor is inside the approval wait: control must already be
      // enrolled (this mock only runs after enrollment).
      const gateDecision = await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_pending_1",
        toolName: "execute_command",
        input: { command: "ls -la" },
      });
      expect(gateDecision).toEqual({ kind: "execute" });
      await input.toolExecutionRecorder.settle("tc_pending_1", {
        type: "text",
        value: "done",
      });
      void gate;
      return RUN_RESULT;
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), {
        runId,
        approval: { requiredTools: ["execute_command"] },
      }),
      store: shared,
    });

    // Pending: durable approval, no tool operation, no model reservation.
    await vi.waitFor(async () => {
      const approvals = await shared.listApprovals(runId);
      expect(approvals).toHaveLength(1);
      approvalId = approvals[0].approvalId;
    });
    expect(await shared.listToolOperations(runId)).toEqual([]);
    expect(await shared.listModelAttempts(runId)).toEqual([]);
    expect(await shared.getControl(runId)).toMatchObject({
      intent: "run",
      runId,
    });

    // Resolution unblocks the executor; the intent is accepted afterward.
    await shared.resolveApproval(runId, approvalId, "approved");
    const outcome = await outcomePromise;
    expect(outcome.started).toBe(true);
    expect(outcome.record.status).toBe("completed");
    const ops = await shared.listToolOperations(runId);
    expect(ops.map((o) => o.toolCallId)).toEqual(["tc_pending_1"]);
    expect(ops[0]?.state).toBe("settled");
  });

  it("approval survives a second connection; resolution there unblocks the executor", async () => {
    const { dbPath, store: first } = await openStore();
    store = first;
    const runId = "run_ctrl_reopen";

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      const decision = await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_reopen_1",
        toolName: "execute_command",
        input: { command: "ls -la" },
      });
      expect(decision).toEqual({ kind: "execute" });
      await input.toolExecutionRecorder.settle("tc_reopen_1", {
        type: "text",
        value: "done",
      });
      return RUN_RESULT;
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), {
        runId,
        approval: { requiredTools: ["execute_command"] },
      }),
      store: first,
    });

    // A separate connection (e.g. the CLI) observes the pending decision.
    const second = await openSqliteRunStore(dbPath);
    let approvalId = "";
    let pendingState = "";
    await vi.waitFor(async () => {
      const approvals = await second.listApprovals(runId);
      expect(approvals).toHaveLength(1);
      approvalId = approvals[0].approvalId;
      pendingState = approvals[0].state;
    });
    expect(pendingState).toBe("pending");

    // Resolve through the second connection; the executor's poll observes it.
    const approved = await second.resolveApproval(
      runId,
      approvalId,
      "approved",
    );
    expect(approved.state).toBe("approved");
    second.close();

    const outcome = await outcomePromise;
    expect(outcome.record.status).toBe("completed");
    const ops = await first.listToolOperations(runId);
    expect(ops.map((o) => o.toolCallId)).toEqual(["tc_reopen_1"]);
  });

  it("denial returns the deterministic blocked output: no execute, no tool intent, run completes", async () => {
    const { store: shared } = await openStore();
    store = shared;
    const runId = "run_ctrl_deny";
    let blockedOutput: unknown;

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      const decision = await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_deny_1",
        toolName: "execute_command",
        input: { command: "ls -la" },
      });
      // The denial is a stable blocked result, not an execute permission.
      expect(decision).toEqual({ kind: "reuse", output: DENIED_BY_OPERATOR });
      blockedOutput = decision;
      return RUN_RESULT;
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), {
        runId,
        approval: { requiredTools: ["execute_command"] },
      }),
      store: shared,
    });

    let approvalId = "";
    await vi.waitFor(async () => {
      const approvals = await shared.listApprovals(runId);
      expect(approvals).toHaveLength(1);
      approvalId = approvals[0].approvalId;
    });
    const denied = await shared.resolveApproval(runId, approvalId, "denied");
    expect(denied).toMatchObject({ state: "denied", reason: "user_rejected" });

    const outcome = await outcomePromise;
    expect(outcome.record.status).toBe("completed");
    expect(blockedOutput).toEqual({
      kind: "reuse",
      output: DENIED_BY_OPERATOR,
    });
    // No tool intent was ever accepted for the denied call.
    expect(await shared.listToolOperations(runId)).toEqual([]);
    // A conflicting later decision cannot flip the denial.
    await expect(
      shared.resolveApproval(runId, approvalId, "approved"),
    ).rejects.toThrow();
  });
});

describe("pause and stop intent", () => {
  it("pause saves paused at the dispatch boundary without aborting accepted work", async () => {
    const { store: shared } = await openStore();
    store = shared;
    const runId = "run_ctrl_pause";
    const workDone = gated();

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      // Accepted work: an ungated tool completes and settles.
      const decision = await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_pause_1",
        toolName: "read_file",
        input: { path: "notes.txt" },
      });
      expect(decision).toEqual({ kind: "execute" });
      await input.toolExecutionRecorder.settle("tc_pause_1", {
        type: "text",
        value: "contents",
      });
      workDone.release();
      // Hold between turns; the pause command lands here.
      await new Promise((resolve) => setTimeout(resolve, 50));
      // The next model turn observes the pause and interrupts — without
      // touching the already-settled work above.
      const recorder = getInferenceRecorder();
      if (!recorder) throw new Error("no inference recorder in ALS context");
      await recorder.beforeDispatch(makeAttempt());
      throw new Error("expected the dispatch gate to interrupt");
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), {
        runId,
        approval: { requiredTools: [] },
      }),
      store: shared,
    });

    await workDone.promise;
    const control = await shared.getControl(runId);
    await shared.requestControl(runId, "pause", control?.revision ?? 0);

    // The interruption is an explicit control outcome, not a failure.
    const outcome = await outcomePromise;
    expect(outcome.started).toBe(true);
    expect(outcome.record.status).toBe("paused");
    expect((await shared.getControl(runId))?.intent).toBe("pause");
    // Accepted work was not aborted: it settled before the boundary.
    const ops = await shared.listToolOperations(runId);
    expect(ops[0]).toMatchObject({
      toolCallId: "tc_pause_1",
      state: "settled",
    });
  });

  it("stop persists, cancels the run, and denies the pending approval", async () => {
    const { store: shared } = await openStore();
    store = shared;
    const runId = "run_ctrl_stop";

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      // Blocks inside the approval wait until the stop interrupts it.
      await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_stop_1",
        toolName: "execute_command",
        input: { command: "ls -la" },
      });
      throw new Error("expected the approval wait to interrupt");
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), {
        runId,
        approval: { requiredTools: ["execute_command"] },
      }),
      store: shared,
    });

    let approvalId = "";
    await vi.waitFor(async () => {
      const approvals = await shared.listApprovals(runId);
      expect(approvals).toHaveLength(1);
      approvalId = approvals[0].approvalId;
    });

    const control = await shared.getControl(runId);
    const stopped = await shared.requestControl(
      runId,
      "stop",
      control?.revision ?? 0,
    );
    expect(stopped).toMatchObject({ intent: "stop" });

    const outcome = await outcomePromise;
    expect(outcome.record.status).toBe("cancelled");
    // The stop transaction invalidated the pending decision.
    const approvals = await shared.listApprovals(runId);
    expect(approvals[0]).toMatchObject({
      state: "denied",
      reason: "run_stopped",
    });
    expect(await shared.listToolOperations(runId)).toEqual([]);
    // Stop dominates: a later pause command rejects; approval is impossible.
    const after = await shared.getControl(runId);
    await expect(
      shared.requestControl(runId, "pause", after?.revision ?? 0),
    ).rejects.toThrow();
    await expect(
      shared.resolveApproval(runId, approvalId, "approved"),
    ).rejects.toThrow();
  });
});

describe("control persistence failure and the ungated default", () => {
  it("a control-store failure fails closed: no dispatch, run not completed", async () => {
    const { store: real } = await openStore();
    store = real;
    const runId = "run_ctrl_fail";
    const failing = {
      ...real,
      requestApproval: async () => {
        throw new Error("control disk on fire");
      },
    } as Store;

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_fail_1",
        toolName: "execute_command",
        input: { command: "ls -la" },
      });
      throw new Error("expected the approval request to fail");
    });

    await expect(
      runRecordedAgent({
        spec: baseSpec(tempDir("control-cwd-"), {
          runId,
          approval: { requiredTools: ["execute_command"] },
        }),
        store: failing,
      }),
    ).rejects.toThrow();

    const record = await real.get(runId);
    expect(record?.status).toBe("failed");
    expect(await real.listToolOperations(runId)).toEqual([]);
    expect(await real.listModelAttempts(runId)).toEqual([]);
  });

  it("ungated runs keep the existing behavior: no approvals, tools run, completes", async () => {
    const { store: shared } = await openStore();
    store = shared;
    const runId = "run_ctrl_ungated";

    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      const decision = await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_ungated_1",
        toolName: "read_file",
        input: { path: "notes.txt" },
      });
      expect(decision).toEqual({ kind: "execute" });
      await input.toolExecutionRecorder.settle("tc_ungated_1", {
        type: "text",
        value: "contents",
      });
      return RUN_RESULT;
    });

    const outcome = await runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), { runId }),
      store: shared,
    });

    expect(outcome.started).toBe(true);
    expect(outcome.record.status).toBe("completed");
    expect(await shared.listApprovals(runId)).toEqual([]);
    expect((await shared.listToolOperations(runId))[0]).toMatchObject({
      toolCallId: "tc_ungated_1",
      state: "settled",
    });
    expect(runAgent).toHaveBeenCalledTimes(1);
  });
});

describe("teardown race: a delayed control poll rejection cannot become a success", () => {
  it("holds the first getControl (constructor poll); a later rejected poll fails the run, never completes it", async () => {
    const { store: real } = await openStore();
    store = real;
    const runId = "run_ctrl_teardown";

    // The controller's constructor fires an initial getControl poll; defer
    // only that first call so it is still in flight during teardown, while
    // every later control read (gates) proceeds normally.
    let releaseFirstPoll!: (decision: "resolve" | "reject") => void;
    const firstPoll = new Promise<"resolve" | "reject">((resolve) => {
      releaseFirstPoll = resolve;
    });
    let firstCall = true;
    const getControl = real.getControl.bind(real);
    const spy = vi
      .spyOn(real, "getControl")
      .mockImplementation(async (id: string) => {
        if (firstCall) {
          firstCall = false;
          const decision = await firstPoll;
          if (decision === "reject") throw new Error("poll read failed late");
        }
        return getControl(id);
      });

    // The agent finishes normally while the first poll is still pending.
    runAgent.mockImplementationOnce(async (input: AgentInput) => {
      await primeContext(input);
      const decision = await input.toolExecutionRecorder.beforeExecute({
        toolCallId: "tc_teardown_1",
        toolName: "read_file",
        input: { path: "notes.txt" },
      });
      expect(decision).toEqual({ kind: "execute" });
      await input.toolExecutionRecorder.settle("tc_teardown_1", {
        type: "text",
        value: "contents",
      });
      return RUN_RESULT;
    });

    const outcomePromise = runRecordedAgent({
      spec: baseSpec(tempDir("control-cwd-"), { runId }),
      store: real,
    });

    // Give the run every chance to settle early — dispose must hold the
    // final status until the in-flight poll resolves or rejects.
    await new Promise((resolve) => setTimeout(resolve, 150));
    let settled = false;
    void outcomePromise.then(
      () => (settled = true),
      () => (settled = true),
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(settled).toBe(false);
    expect((await real.get(runId))?.status).not.toBe("completed");

    // The delayed poll now fails: the invocation must fail with the run
    // saved as failed — the completed write was never made.
    releaseFirstPoll("reject");
    await expect(outcomePromise).rejects.toThrow();
    expect((await real.get(runId))?.status).toBe("failed");
    spy.mockRestore();
  });
});
