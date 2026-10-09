// Tool-journal integration pins through the real SDK streamText loop with
// runRecordedAgent's composed recorder wiring — ordering assertions prove
// dispatch gates, not callback simulations.
import type {
  LanguageModelV3GenerateResult,
  LanguageModelV3StreamResult,
} from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { wrapRecordedTools } from "../agents/offSecAgent/recordedTools";
import { RunPersistenceError } from "../runtime/persistenceError";
import { composeRecordedExecution } from "../runtime/recordedExecution";
import type { ContextReference } from "../runtime/runContext";
import { createRunContextRecorder } from "../runtime/runContext";
import { createRunControl } from "../runtime/runControl";
import type {
  RecordedApproval,
  RunControlStore,
} from "../runtime/runControlStore";
import {
  RunControlConflictError,
  RunControlInterruption,
} from "../runtime/runControlStore";
import { createRunInferenceRecorder } from "../runtime/runInference";
import type { RunModelStore } from "../runtime/runModelStore";
import type {
  RecordedToolInput,
  RecordedToolOperation,
  RunToolStore,
} from "../runtime/runToolStore";
import { createRunToolRecorder } from "../runtime/runTools";
import { runWithInferenceRecorder } from "./inference-attempt";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const { streamResponse } = await import("./ai");

// The journal's TOOL_POLICIES allowlist fixes which tool names dispatch, so
// the fixture must use a journaled one.
const TOOL_NAME = "read_file";
const MODEL = "claude-haiku-4-5";
const RUN_ID = "run_recorded_tools";
const EXECUTION_ATTEMPT_ID = "exec_00000000-0000-4000-8000-000000000001";
const EVIDENCE_ROOT = "/tmp/recorded-tools-session";
const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

type StoreCall =
  | { kind: "start"; input: RecordedToolInput }
  | {
      kind: "settle";
      toolCallId: string;
      output: unknown;
      evidence: { rootPath: string; files: unknown[] };
    }
  | { kind: "unknown"; toolCallId: string }
  | { kind: "effect"; toolCallId: string };

function makeToolStore(fail?: { settle?: unknown }) {
  const calls: StoreCall[] = [];
  const operations = new Map<string, RecordedToolOperation>();
  const store: RunToolStore = {
    initializeToolJournal: async () => {},
    hasToolJournal: async () => true,
    startToolOperation: async (
      _runId: string,
      executionAttemptId: string,
      input: RecordedToolInput,
    ) => {
      calls.push({ kind: "start", input });
      const operation: RecordedToolOperation = {
        schemaVersion: 1,
        operationId: `op_${input.toolCallId}`,
        executionAttemptId,
        sequence: calls.length,
        context: { epoch: 1, revision: 1 },
        state: "started",
        ...input,
        startedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      operations.set(input.toolCallId, operation);
      return { created: true, operation };
    },
    settleToolOperation: async (
      _runId: string,
      _executionAttemptId: string,
      toolCallId: string,
      output: never,
      evidence: { rootPath: string; files: unknown[] },
    ) => {
      calls.push({
        kind: "settle",
        toolCallId,
        output: structuredClone(output),
        evidence,
      });
      if (fail?.settle) throw fail.settle;
    },
    markToolOutcomeUnknown: async (
      _runId: string,
      _executionAttemptId: string,
      toolCallId: string,
    ) => {
      calls.push({ kind: "unknown", toolCallId });
    },
    listToolOperations: async () => [...operations.values()],
  };
  return { calls, store };
}

/** Minimal in-memory control store the test drives like an operator client. */
function makeControlStore() {
  let control = {
    schemaVersion: 1 as const,
    runId: RUN_ID,
    executionAttemptId: EXECUTION_ATTEMPT_ID,
    intent: "run" as "run" | "pause" | "stop",
    revision: 0,
    updatedAt: new Date().toISOString(),
  };
  const approvals = new Map<string, RecordedApproval>();
  const store: RunControlStore = {
    initializeControl: async () => {},
    getControl: async () => structuredClone(control),
    requestControl: async (
      _runId: string,
      intent: "pause" | "stop",
      expectedRevision: number,
    ) => {
      if (control.intent === "stop" || control.revision !== expectedRevision) {
        throw new RunControlConflictError("control revision changed");
      }
      control = {
        ...control,
        intent,
        revision: control.revision + 1,
        updatedAt: new Date().toISOString(),
      };
      return structuredClone(control);
    },
    requestApproval: async (
      _runId: string,
      _executionAttemptId: string,
      request: { toolCallId: string; toolName: string; input: unknown },
    ) => {
      const approvalId = `apr_${request.toolCallId}`;
      const existing = approvals.get(approvalId);
      if (existing) return structuredClone(existing);
      const record: RecordedApproval = {
        schemaVersion: 1,
        approvalId,
        runId: RUN_ID,
        executionAttemptId: EXECUTION_ATTEMPT_ID,
        toolCallId: request.toolCallId,
        toolName: request.toolName,
        input: request.input,
        specDigest: "digest",
        context: { epoch: 1, revision: 1 },
        state: "pending",
        createdAt: new Date().toISOString(),
      };
      approvals.set(approvalId, record);
      return structuredClone(record);
    },
    getApproval: async (_runId: string, approvalId: string) => {
      const record = approvals.get(approvalId);
      return record ? structuredClone(record) : undefined;
    },
    listApprovals: async () =>
      [...approvals.values()].map((record) => structuredClone(record)),
    resolveApproval: async (
      _runId: string,
      approvalId: string,
      decision: "approved" | "denied",
    ) => {
      const record = approvals.get(approvalId);
      if (!record) throw new Error("Approval not found");
      if (record.state === decision) return structuredClone(record);
      if (record.state !== "pending") {
        throw new RunControlConflictError("approval already decided");
      }
      const next: RecordedApproval = {
        ...record,
        state: decision,
        ...(decision === "denied" ? { reason: "user_rejected" as const } : {}),
        decidedAt: new Date().toISOString(),
      };
      approvals.set(approvalId, next);
      return structuredClone(next);
    },
  };
  return {
    store,
    approvalIds: () => [...approvals.keys()],
  };
}

/** Wires the recorders exactly as runRecordedAgent composes them. */
function makeHarness(
  fail?: { settle?: unknown },
  options?: { requiredTools?: string[] },
) {
  const tool = makeToolStore(fail);
  const controlStore = makeControlStore();
  const control = createRunControl({
    runId: RUN_ID,
    executionAttemptId: EXECUTION_ATTEMPT_ID,
    store: controlStore.store,
    requiredTools: options?.requiredTools ?? [],
    pollIntervalMs: 25,
  });
  liveControls.push(control);
  const toolRecorder = createRunToolRecorder({
    runId: RUN_ID,
    executionAttemptId: EXECUTION_ATTEMPT_ID,
    store: tool.store,
    collectEvidence: async () => ({
      rootPath: EVIDENCE_ROOT,
      files: [],
    }),
    beforeTool: control.beforeTool,
  });
  const modelStore = {
    startModelAttempt: async () => {},
    observeModelToolCall: async () => {},
    settleModelAttempt: async () => {},
    recordRetry: async () => {},
    listModelAttempts: async () => [],
    listRetries: async () => [],
  } as unknown as RunModelStore;
  const inferenceRecorder = createRunInferenceRecorder({
    runId: RUN_ID,
    executionAttemptId: EXECUTION_ATTEMPT_ID,
    store: modelStore,
  });
  let contextRef: ContextReference | undefined;
  let contextCommits = 0;
  const contextStore = {
    // The adapter drains the tool journal before the underlying context
    // write, mirroring the production commitContext wiring.
    commitContext: async (
      _runId: string,
      _attemptId: string,
      _revision: number,
      change: { kind: string },
    ) => {
      await toolRecorder.flush();
      await control.flush();
      contextCommits++;
      contextRef = !contextRef
        ? { epoch: 1, revision: 1 }
        : change.kind === "append"
          ? { epoch: contextRef.epoch, revision: contextRef.revision + 1 }
          : { epoch: contextRef.epoch + 1, revision: contextRef.revision + 1 };
      return contextRef;
    },
    getContext: async () => undefined,
  };
  return {
    calls: tool.calls,
    toolRecorder,
    controlStore: controlStore.store,
    approvalIds: controlStore.approvalIds,
    contextCommits: () => contextCommits,
    executionRecorder: composeRecordedExecution(
      inferenceRecorder,
      () => toolRecorder,
      () => control,
    ),
    contextRecorder: createRunContextRecorder({
      runId: RUN_ID,
      attemptId: EXECUTION_ATTEMPT_ID,
      store: contextStore,
    }),
  };
}

const liveControls: Array<ReturnType<typeof createRunControl>> = [];

function streamOf(chunks: unknown[]): LanguageModelV3StreamResult {
  return {
    stream: simulateReadableStream({ chunks }),
  } as LanguageModelV3StreamResult;
}

function streamStartChunk() {
  return { type: "stream-start" as const, warnings: [] };
}

function toolCallChunk(toolCallId: string, input: string) {
  return {
    type: "tool-call" as const,
    toolCallId,
    toolName: TOOL_NAME,
    input,
  };
}

function finishChunk() {
  return {
    type: "finish" as const,
    finishReason: { unified: "stop" as const, raw: "stop" },
    usage,
  };
}

function textStep(id: string) {
  return [
    { type: "text-start" as const, id },
    { type: "text-delta" as const, id, delta: "done" },
    { type: "text-end" as const, id },
  ];
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    /* consume the SDK lifecycle */
  }
}

async function drainParts(stream: { fullStream: AsyncIterable<unknown> }) {
  const parts: Array<Record<string, unknown>> = [];
  for await (const part of stream.fullStream) {
    parts.push(part as Record<string, unknown>);
  }
  return parts;
}

const toolSchema = z.object({ q: z.string() });

function wrappedJournaledTool(
  recorder: ReturnType<typeof makeHarness>["toolRecorder"],
  execute: (input: { q: string }) => unknown,
) {
  return wrapRecordedTools(
    {
      [TOOL_NAME]: {
        description: "probe fixture",
        inputSchema: toolSchema,
        execute: async (input: { q: string }) => execute(input),
      },
    },
    recorder,
  );
}

function startRow(calls: StoreCall[], toolCallId: string): unknown {
  const row = calls.find(
    (call) => call.kind === "start" && call.input.toolCallId === toolCallId,
  );
  if (row?.kind !== "start") {
    throw new Error(`missing start row ${toolCallId}`);
  }
  return row.input.input;
}

function settleRow(
  calls: StoreCall[],
  toolCallId: string,
): { output: unknown; evidence: { rootPath: string } } {
  const row = calls.find(
    (call) => call.kind === "settle" && call.toolCallId === toolCallId,
  );
  if (row?.kind !== "settle") {
    throw new Error(`missing settle row ${toolCallId}`);
  }
  return { output: row.output, evidence: row.evidence };
}

beforeEach(() => {
  state.model = undefined;
});

afterEach(async () => {
  for (const control of liveControls.splice(0)) {
    await control.dispose();
  }
});

describe("tool journal at the execution boundary (real SDK)", () => {
  it("pins inside the second dispatch: intent precedes effect and exact settlement precedes the next turn", async () => {
    const harness = makeHarness();
    let journalAtSecondDispatch: StoreCall[] | undefined;
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () =>
        streamOf([
          streamStartChunk(),
          toolCallChunk("c1", '{"q":"x"}'),
          finishChunk(),
        ]),
      )
      .mockImplementationOnce(async () => {
        journalAtSecondDispatch = [...harness.calls];
        return streamOf([...textStep("t1"), finishChunk()]);
      });
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(2),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, (input) => {
            harness.calls.push({ kind: "effect", toolCallId: "c1" });
            expect(input).toEqual({ q: "x" });
            return "ok";
          }),
        }),
      ),
    );

    expect(doStream).toHaveBeenCalledTimes(2);
    // The second dispatch observed the full settled exchange already journaled.
    const snapshot = journalAtSecondDispatch ?? [];
    const startIndex = snapshot.findIndex(
      (call) => call.kind === "start" && call.input.toolCallId === "c1",
    );
    const effectIndex = snapshot.findIndex((call) => call.kind === "effect");
    const settleIndex = snapshot.findIndex(
      (call) => call.kind === "settle" && call.toolCallId === "c1",
    );
    expect(startIndex).toBeGreaterThanOrEqual(0);
    expect(effectIndex).toBeGreaterThan(startIndex);
    expect(settleIndex).toBeGreaterThan(effectIndex);
    const settle = settleRow(snapshot, "c1");
    expect(settle.output).toEqual({ type: "text", value: "ok" });
    expect(settle.evidence.rootPath).toBe(EVIDENCE_ROOT);
    expect(snapshot.filter((call) => call.kind === "settle")).toHaveLength(1);
    await harness.toolRecorder.flush();
  });

  it("preserves identities for two parallel tool calls in one step", async () => {
    const harness = makeHarness();
    let journalAtSecondDispatch: StoreCall[] | undefined;
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () =>
        streamOf([
          streamStartChunk(),
          toolCallChunk("c1", '{"q":"a"}'),
          toolCallChunk("c2", '{"q":"b"}'),
          finishChunk(),
        ]),
      )
      .mockImplementationOnce(async () => {
        journalAtSecondDispatch = [...harness.calls];
        return streamOf([...textStep("t1"), finishChunk()]);
      });
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe twice",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(2),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, (input) => {
            harness.calls.push({ kind: "effect", toolCallId: input.q });
            return `out-${input.q}`;
          }),
        }),
      ),
    );

    expect(doStream).toHaveBeenCalledTimes(2);
    const snapshot = journalAtSecondDispatch ?? [];
    expect(startRow(snapshot, "c1")).toEqual({ q: "a" });
    expect(startRow(snapshot, "c2")).toEqual({ q: "b" });
    expect(settleRow(snapshot, "c1").output).toEqual({
      type: "text",
      value: "out-a",
    });
    expect(settleRow(snapshot, "c2").output).toEqual({
      type: "text",
      value: "out-b",
    });
    expect(snapshot.filter((call) => call.kind === "effect")).toHaveLength(2);
    await harness.toolRecorder.flush();
  });

  it("blocks the second provider dispatch when settlement fails, even though the SDK converts the execute throw to a tool-error", async () => {
    const harness = makeHarness({
      settle: new Error("tool journal write failed"),
    });
    let providerCalls = 0;
    const doStream = vi.fn(async () => {
      providerCalls++;
      return providerCalls === 1
        ? streamOf([
            streamStartChunk(),
            toolCallChunk("c1", '{"q":"x"}'),
            finishChunk(),
          ])
        : streamOf([...textStep("t1"), finishChunk()]);
    });
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    const consumed = runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(2),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, (input) => {
            harness.calls.push({ kind: "effect", toolCallId: "c1" });
            expect(input).toEqual({ q: "x" });
            return "ok";
          }),
        }),
      ),
    );

    // The composed recorder drains the latched tool journal before every
    // dispatch and before each context commit's underlying write: the SDK's
    // tool-error conversion cannot carry the run to a second provider call,
    // and the tool step's context commit never lands.
    await expect(consumed).rejects.toBeInstanceOf(RunPersistenceError);
    expect(providerCalls).toBe(1);
    expect(harness.contextCommits()).toBe(1);
    await expect(harness.executionRecorder.flush()).rejects.toBeInstanceOf(
      RunPersistenceError,
    );
  });

  it("records only the validated, executed input when the SDK repairs an invalid tool call", async () => {
    const harness = makeHarness();
    const executedInputs: Array<{ q: string }> = [];
    const doStream = vi.fn(async () =>
      streamOf([
        streamStartChunk(),
        toolCallChunk("c1", '{"q":123}'),
        finishChunk(),
      ]),
    );
    const doGenerate = vi.fn(
      async (): Promise<LanguageModelV3GenerateResult> => ({
        content: [{ type: "text", text: '{"q":"repaired"}' }],
        finishReason: { unified: "stop", raw: "stop" },
        usage,
        warnings: [],
      }),
    );
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream,
      doGenerate,
    });

    await runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(1),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, (input) => {
            executedInputs.push(input);
            return `out-${input.q}`;
          }),
        }),
      ),
    );

    // Only the repaired, executed input is journaled — never the invalid original.
    expect(executedInputs).toEqual([{ q: "repaired" }]);
    const starts = harness.calls.filter((call) => call.kind === "start");
    expect(starts).toHaveLength(1);
    expect(startRow(harness.calls, "c1")).toEqual({ q: "repaired" });
    expect(
      harness.calls.some((call) => JSON.stringify(call).includes("123")),
    ).toBe(false);
    expect(settleRow(harness.calls, "c1").output).toEqual({
      type: "text",
      value: "out-repaired",
    });
    await harness.toolRecorder.flush();
  });

  it("normalizes legal undefined members once: persisted receipt equals the served conversion, raw output unchanged", async () => {
    const harness = makeHarness();
    const raw = { status: 200, error: undefined };
    let modelToolOutput: unknown;
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () =>
        streamOf([
          streamStartChunk(),
          toolCallChunk("c1", '{"q":"x"}'),
          finishChunk(),
        ]),
      )
      .mockImplementationOnce(
        async (options: { prompt?: Array<Record<string, unknown>> }) => {
          for (const message of options.prompt ?? []) {
            for (const part of (message.content ?? []) as Array<
              Record<string, unknown>
            >) {
              if (part.type === "tool-result") {
                modelToolOutput = part.output;
              }
            }
          }
          return streamOf([...textStep("t1"), finishChunk()]);
        },
      );
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    const parts = await runWithInferenceRecorder(
      harness.executionRecorder,
      () =>
        drainParts(
          streamResponse({
            model: MODEL,
            prompt: "probe",
            silent: true,
            sessionId: "ses_tools",
            stopWhen: stepCountIs(2),
            contextRecorder: harness.contextRecorder,
            tools: wrappedJournaledTool(harness.toolRecorder, () => raw),
          }),
        ),
    );

    const settle = settleRow(harness.calls, "c1");
    expect(settle.output).toStrictEqual({
      type: "json",
      value: { status: 200 },
    });
    // The conversion served to the next model turn equals the receipt.
    expect(modelToolOutput).toStrictEqual(settle.output);
    // The UI-facing stream part and the raw result keep the in-memory shape.
    const toolResult = parts.find((part) => part.type === "tool-result") as {
      output: unknown;
    };
    expect(toolResult.output).toStrictEqual({ status: 200, error: undefined });
    expect("error" in raw).toBe(true);
    expect(raw.error).toBeUndefined();
    await harness.toolRecorder.flush();
  });

  it("marks the operation unknown without settling when output fails JSON validation", async () => {
    const harness = makeHarness();
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () =>
        streamOf([
          streamStartChunk(),
          toolCallChunk("c1", '{"q":"x"}'),
          finishChunk(),
        ]),
      )
      .mockImplementationOnce(async () =>
        streamOf([...textStep("t1"), finishChunk()]),
      );
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    // NaN and Infinity pass no JSON transport — the run must not coerce them.
    await runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(2),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, () => ({
            status: 200,
            nan: Number.NaN,
            inf: Number.POSITIVE_INFINITY,
          })),
        }),
      ),
    );

    expect(harness.calls.filter((call) => call.kind === "settle")).toHaveLength(
      0,
    );
    expect(
      harness.calls.some(
        (call) => call.kind === "unknown" && call.toolCallId === "c1",
      ),
    ).toBe(true);
    // Unknown is honest, not latched: the SDK's tool-error conversion
    // continues the run.
    expect(doStream).toHaveBeenCalledTimes(2);
    await harness.toolRecorder.flush();
  });
});

describe("durable control at the execution boundary (real SDK)", () => {
  it("cooperative pause: settled work checkpoints, the next dispatch is interrupted, and the interruption survives the SDK", async () => {
    const harness = makeHarness();
    let providerCalls = 0;
    const doStream = vi.fn(async () => {
      providerCalls++;
      return providerCalls === 1
        ? streamOf([
            streamStartChunk(),
            toolCallChunk("c1", '{"q":"x"}'),
            finishChunk(),
          ])
        : streamOf([...textStep("t1"), finishChunk()]);
    });
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    const consumed = runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(2),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, (input) => {
            harness.calls.push({ kind: "effect", toolCallId: "c1" });
            expect(input).toEqual({ q: "x" });
            // The operator pauses mid-tool: accepted work still finishes.
            return (async () => {
              const control = await harness.controlStore.getControl(RUN_ID);
              if (!control) throw new Error("Expected enrolled control");
              await harness.controlStore.requestControl(
                RUN_ID,
                "pause",
                control.revision,
              );
              return "ok";
            })();
          }),
        }),
      ),
    );

    const error = await consumed.then(
      () => {
        throw new Error("expected the run to be interrupted");
      },
      (cause: unknown) => cause,
    );
    expect(error).toBeInstanceOf(RunControlInterruption);
    expect((error as Error).message).toContain("paused before dispatch");
    expect(providerCalls).toBe(1);
    // Accepted work finished: effect, intent, and settlement all journaled.
    const settle = settleRow(harness.calls, "c1");
    expect(settle.output).toEqual({ type: "text", value: "ok" });
    expect(harness.calls.some((call) => call.kind === "effect")).toBe(true);
    // The tool step's checkpoint committed despite the persisted pause.
    expect(harness.contextCommits()).toBe(2);
    // The composed flush surfaces the gate-observed interruption.
    await expect(harness.executionRecorder.flush()).rejects.toBeInstanceOf(
      RunControlInterruption,
    );
    const control = await harness.controlStore.getControl(RUN_ID);
    expect(control?.intent).toBe("pause");
  });

  it("denied approval blocks before intent: no executed effect, stable blocked result served to the model", async () => {
    const harness = makeHarness(undefined, { requiredTools: [TOOL_NAME] });
    const executedInputs: Array<{ q: string }> = [];
    let providerCalls = 0;
    let modelToolOutput: unknown;
    const doStream = vi.fn(
      async (options: { prompt?: Array<Record<string, unknown>> }) => {
        providerCalls++;
        if (providerCalls === 2) {
          for (const message of options.prompt ?? []) {
            for (const part of (message.content ?? []) as Array<
              Record<string, unknown>
            >) {
              if (part.type === "tool-result") {
                modelToolOutput = part.output;
              }
            }
          }
        }
        return providerCalls === 1
          ? streamOf([
              streamStartChunk(),
              toolCallChunk("c1", '{"q":"x"}'),
              finishChunk(),
            ])
          : streamOf([...textStep("t1"), finishChunk()]);
      },
    );
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    const consumed = runWithInferenceRecorder(harness.executionRecorder, () =>
      drain(
        streamResponse({
          model: MODEL,
          prompt: "probe",
          silent: true,
          sessionId: "ses_tools",
          stopWhen: stepCountIs(2),
          contextRecorder: harness.contextRecorder,
          tools: wrappedJournaledTool(harness.toolRecorder, (input) => {
            executedInputs.push(input);
            return "ok";
          }),
        }),
      ),
    );

    // The operator denies while the executor waits on the pending approval.
    await vi.waitFor(() => expect(harness.approvalIds().length).toBe(1));
    const [approvalId] = harness.approvalIds();
    await harness.controlStore.resolveApproval(RUN_ID, approvalId, "denied");
    await consumed;

    // No intent, no effect, no settlement — only the durable decision.
    expect(executedInputs).toEqual([]);
    expect(harness.calls.filter((call) => call.kind === "start")).toHaveLength(
      0,
    );
    expect(harness.calls.filter((call) => call.kind === "settle")).toHaveLength(
      0,
    );
    // The next model turn sees the stable blocked output.
    expect(modelToolOutput).toStrictEqual({
      type: "json",
      value: { blocked: true, reason: "Denied by operator" },
    });
    expect(providerCalls).toBe(2);
    const approval = await harness.controlStore.getApproval(RUN_ID, approvalId);
    expect(approval?.state).toBe("denied");
    expect(approval?.reason).toBe("user_rejected");
  });
});
