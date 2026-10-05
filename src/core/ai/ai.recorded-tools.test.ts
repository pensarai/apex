// Tool-journal integration pins through the real SDK streamText loop with
// runRecordedAgent's composed recorder wiring — ordering assertions prove
// dispatch gates, not callback simulations.
import type {
  LanguageModelV3GenerateResult,
  LanguageModelV3StreamResult,
} from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { wrapRecordedTools } from "../agents/offSecAgent/recordedTools";
import { RunPersistenceError } from "../runtime/persistenceError";
import { composeRecordedExecution } from "../runtime/recordedExecution";
import type { ContextReference } from "../runtime/runContext";
import { createRunContextRecorder } from "../runtime/runContext";
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

/** Wires the recorders exactly as runRecordedAgent composes them. */
function makeHarness(fail?: { settle?: unknown }) {
  const tool = makeToolStore(fail);
  const toolRecorder = createRunToolRecorder({
    runId: RUN_ID,
    executionAttemptId: EXECUTION_ATTEMPT_ID,
    store: tool.store,
    collectEvidence: async () => ({
      rootPath: EVIDENCE_ROOT,
      files: [],
    }),
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
    contextCommits: () => contextCommits,
    executionRecorder: composeRecordedExecution(
      inferenceRecorder,
      () => toolRecorder,
    ),
    contextRecorder: createRunContextRecorder({
      runId: RUN_ID,
      attemptId: EXECUTION_ATTEMPT_ID,
      store: contextStore,
    }),
  };
}

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
