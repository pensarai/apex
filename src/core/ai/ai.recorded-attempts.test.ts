import {
  APICallError,
  type LanguageModelV3GenerateResult,
  type LanguageModelV3StreamPart,
  type LanguageModelV3StreamResult,
} from "@ai-sdk/provider";
import { type ModelMessage, RetryError, simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { RunPersistenceError } from "../runtime/persistenceError";
import { createRunInferenceRecorder } from "../runtime/runInference";
import type { RunModelStore } from "../runtime/runModelStore";
import type {
  InferenceAttempt,
  ModelRetryDecision,
  ObservedModelToolCall,
} from "./inference-attempt";
import { runWithInferenceRecorder } from "./inference-attempt";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const { streamResponse, generateObjectResponse } = await import("./ai");

const MODEL = "claude-haiku-4-5";
const RUN_ID = "run_recorded_attempts";
const EXECUTION_ATTEMPT_ID = "exec_00000000-0000-4000-8000-000000000001";
const usage = {
  inputTokens: { total: 100, noCache: 100, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 10, text: 10, reasoning: undefined },
};

type StoreCall =
  | { kind: "start"; attempt: InferenceAttempt }
  | { kind: "tool"; attemptId: string; call: ObservedModelToolCall }
  | { kind: "settle"; attempt: InferenceAttempt }
  | { kind: "retry"; decision: ModelRetryDecision };

function makeStore(fail?: {
  start?: unknown;
  /** When set with fail.start, only the Nth start call fails (1-based). */
  startOnCall?: number;
  tool?: unknown;
  settle?: unknown;
}) {
  const calls: StoreCall[] = [];
  const store = {
    startModelAttempt: async (
      _runId: string,
      _executionAttemptId: string,
      attempt: InferenceAttempt,
    ) => {
      const startCount = calls.filter((call) => call.kind === "start").length;
      calls.push({ kind: "start", attempt });
      if (
        fail?.start !== undefined &&
        (fail.startOnCall === undefined || startCount + 1 === fail.startOnCall)
      ) {
        throw fail.start;
      }
    },
    observeModelToolCall: async (
      _runId: string,
      _executionAttemptId: string,
      attemptId: string,
      call: ObservedModelToolCall,
    ) => {
      calls.push({ kind: "tool", attemptId, call });
      if (fail?.tool) throw fail.tool;
    },
    settleModelAttempt: async (
      _runId: string,
      _executionAttemptId: string,
      attempt: InferenceAttempt,
    ) => {
      calls.push({ kind: "settle", attempt });
      if (fail?.settle) throw fail.settle;
    },
    recordRetry: async (
      _runId: string,
      _executionAttemptId: string,
      decision: ModelRetryDecision,
    ) => {
      calls.push({ kind: "retry", decision });
    },
    listModelAttempts: async () => [],
    listRetries: async () => [],
  } as unknown as RunModelStore;

  return {
    calls,
    recorder: createRunInferenceRecorder({
      runId: RUN_ID,
      executionAttemptId: EXECUTION_ATTEMPT_ID,
      store,
    }),
  };
}

function textStream(text = "Done"): LanguageModelV3StreamResult {
  const chunks: LanguageModelV3StreamPart[] = [
    { type: "text-start", id: "t0" },
    { type: "text-delta", id: "t0", delta: text },
    { type: "text-end", id: "t0" },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage,
    },
  ];
  return { stream: simulateReadableStream({ chunks }) };
}

function errorStream(message: string): LanguageModelV3StreamResult {
  const chunks: LanguageModelV3StreamPart[] = [
    { type: "stream-start", warnings: [] },
    { type: "error", error: new Error(message) },
  ];
  return { stream: simulateReadableStream({ chunks }) };
}

function toolCallStream(input: string): LanguageModelV3StreamResult {
  const chunks: LanguageModelV3StreamPart[] = [
    { type: "stream-start", warnings: [] },
    {
      type: "tool-call",
      toolCallId: "tc_probe",
      toolName: "probe",
      input,
    },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage,
    },
  ];
  return { stream: simulateReadableStream({ chunks }) };
}

function generated(text: string): LanguageModelV3GenerateResult {
  return {
    content: [{ type: "text", text }],
    finishReason: { unified: "stop", raw: "stop" },
    usage,
    warnings: [],
  };
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    /* consume the SDK lifecycle */
  }
}

const probeTool = (execute: ReturnType<typeof makeProbeExecute>) => ({
  probe: {
    inputSchema: z.object({ target: z.string() }),
    execute,
  },
});

function makeProbeExecute() {
  return vi.fn(async (_input: { target: string }) => "probed");
}

beforeEach(() => {
  state.model = undefined;
});

describe("recorded attempts at the model boundary", () => {
  it("records every physical SDK retry with shared retry lineage", async () => {
    const { recorder, calls } = makeStore();
    const doStream = vi
      .fn()
      .mockRejectedValueOnce(
        new APICallError({
          message: "429 too many requests",
          url: "https://provider.test/v1",
          requestBodyValues: {},
          statusCode: 429,
          isRetryable: true,
        }),
      )
      .mockImplementationOnce(async () => textStream());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await runWithInferenceRecorder(recorder, async () => {
      const response = streamResponse({
        prompt: "do work",
        model: MODEL,
        silent: true,
        sessionId: "ses_recorded",
      });
      await drain(response);
    });

    expect(doStream).toHaveBeenCalledTimes(2);
    const starts = calls
      .filter((call) => call.kind === "start")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    expect(starts).toHaveLength(2);
    const [first, second] = starts;
    expect(second.attemptId).not.toBe(first.attemptId);
    expect(second.idempotencyKey).toBe(first.idempotencyKey);
    expect(second.attribution.rootAttemptId).toBe(
      first.attribution.rootAttemptId,
    );
    expect(second.lineage.sequence).toBe(2);
    expect(second.lineage.previousAttemptId).toBe(first.attemptId);
    const settles = calls
      .filter((call) => call.kind === "settle")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    expect(settles.map((attempt) => attempt.lifecycle)).toEqual([
      "retried",
      "completed",
    ]);
    await recorder.flush();
  });

  it("blocks the provider call when the pre-dispatch write fails", async () => {
    const { recorder } = makeStore({
      start: new Error("model store unreachable"),
    });
    const doStream = vi.fn(async () => textStream());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await expect(
      runWithInferenceRecorder(recorder, async () => {
        const response = streamResponse({
          prompt: "do work",
          model: MODEL,
          silent: true,
          sessionId: "ses_recorded",
        });
        await drain(response);
      }),
    ).rejects.toThrow(RunPersistenceError);
    expect(doStream).not.toHaveBeenCalled();
    await expect(recorder.flush()).rejects.toThrow(RunPersistenceError);
  });

  it("prevents tool execution when the tool-call write fails", async () => {
    const { recorder, calls } = makeStore({
      tool: new Error("tool store unreachable"),
    });
    const execute = makeProbeExecute();
    const doStream = vi.fn(async () => toolCallStream('{"target":"x"}'));
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await expect(
      runWithInferenceRecorder(recorder, async () => {
        const response = streamResponse({
          prompt: "probe the target",
          model: MODEL,
          silent: true,
          sessionId: "ses_recorded",
          tools: probeTool(execute),
        });
        await drain(response);
      }),
    ).rejects.toThrow(RunPersistenceError);
    expect(execute).not.toHaveBeenCalled();
    expect(calls.filter((call) => call.kind === "tool")).toHaveLength(1);
    await expect(recorder.flush()).rejects.toThrow(RunPersistenceError);
  });

  it("flush surfaces a settlement failure and blocks the next dispatch", async () => {
    const { recorder } = makeStore({
      settle: new Error("settlement store unreachable"),
    });
    const doStream = vi.fn(async () => textStream());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    // First run completes: settlement is enqueued synchronously and never
    // blocks the stream.
    await runWithInferenceRecorder(recorder, async () => {
      const response = streamResponse({
        prompt: "first run",
        model: MODEL,
        silent: true,
        sessionId: "ses_recorded",
      });
      await drain(response);
    });

    // The latched failure blocks the next physical dispatch.
    await expect(
      runWithInferenceRecorder(recorder, async () => {
        const response = streamResponse({
          prompt: "second run",
          model: MODEL,
          silent: true,
          sessionId: "ses_recorded",
        });
        await drain(response);
      }),
    ).rejects.toThrow(RunPersistenceError);
    expect(doStream).toHaveBeenCalledTimes(1);
    await expect(recorder.flush()).rejects.toThrow(RunPersistenceError);
  });

  it("persists the stream rate-limit decision before the re-dispatch", async () => {
    const { recorder, calls } = makeStore();
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => errorStream("rate limit exceeded"))
      .mockImplementationOnce(async () => textStream());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await runWithInferenceRecorder(recorder, async () => {
      const response = streamResponse({
        prompt: "rate-limited work",
        model: MODEL,
        silent: true,
        sessionId: "ses_recorded",
      });
      await drain(response);
    });

    expect(doStream).toHaveBeenCalledTimes(2);
    const starts = calls
      .filter((call) => call.kind === "start")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    expect(starts).toHaveLength(2);
    // The native recovery path reuses the wrapped model inside the original
    // operation scope, so the outer retry consumes the retained pending
    // failure and shares the retry lineage (PDR-011: keep SDK lineage).
    expect(starts[1].idempotencyKey).toBe(starts[0].idempotencyKey);
    expect(starts[1].lineage.sequence).toBe(2);
    expect(starts[1].lineage.previousAttemptId).toBe(starts[0].attemptId);
    const retryIndex = calls.findIndex((call) => call.kind === "retry");
    expect(retryIndex).toBeGreaterThan(-1);
    expect(calls[retryIndex]).toEqual({
      kind: "retry",
      decision: {
        authority: "stream-rate-limit",
        count: 1,
        maxRetries: 20,
        delayMs: 1000,
      },
    });
    const secondStartIndex = calls.findLastIndex(
      (call) => call.kind === "start",
    );
    expect(secondStartIndex).toBeGreaterThan(-1);
    expect(retryIndex).toBeLessThan(secondStartIndex);
  });

  it("persists the object rate-limit decision before the re-dispatch", async () => {
    const { recorder, calls } = makeStore();
    const doGenerate = vi
      .fn()
      .mockRejectedValueOnce(new Error("rate limit exceeded"))
      .mockImplementationOnce(async () => generated('{"ok":true}'));
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doGenerate,
    });

    const output = await runWithInferenceRecorder(recorder, () =>
      generateObjectResponse({
        model: MODEL,
        schema: z.object({ ok: z.boolean() }),
        prompt: "judge the result",
        sessionId: "ses_recorded",
      }),
    );

    expect(output).toEqual({ ok: true });
    expect(doGenerate).toHaveBeenCalledTimes(2);
    const retryIndex = calls.findIndex((call) => call.kind === "retry");
    expect(retryIndex).toBeGreaterThan(-1);
    expect(calls[retryIndex]).toEqual({
      kind: "retry",
      decision: {
        authority: "object-rate-limit",
        count: 1,
        maxRetries: 8,
        delayMs: 1000,
      },
    });
    const starts = calls
      .filter((call) => call.kind === "start")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    expect(starts).toHaveLength(2);
    expect(retryIndex).toBeLessThan(
      calls.findLastIndex((call) => call.kind === "start"),
    );
  });

  it("records the compaction summarization as an auxiliary attempt via ALS", async () => {
    const { recorder, calls } = makeStore();
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => textStream("A compact summary"),
      doGenerate: async () => generated("A compact summary"),
    });
    const messages: ModelMessage[] = [
      { role: "user", content: "irreducible ".repeat(100_000) },
    ];

    await runWithInferenceRecorder(recorder, async () => {
      const response = streamResponse({
        prompt: "original task",
        model: MODEL,
        silent: true,
        sessionId: "ses_recorded",
        messages,
      });
      await drain(response);
    });

    const starts = calls
      .filter((call) => call.kind === "start")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    // The primary attempt plus the summarization auxiliary both persist
    // under the same execution attempt, the auxiliary tagged with its own
    // operation kind.
    expect(starts.length).toBeGreaterThanOrEqual(2);
    expect(
      starts.filter((attempt) => attempt.operationKind === "context.summarize"),
    ).toHaveLength(1);
    expect(
      new Set(starts.map((attempt) => attempt.attribution.rootAttemptId)).size,
    ).toBe(starts.length);
    // The restart decision is recorded before the resumed dispatch.
    const retries = calls.filter((call) => call.kind === "retry");
    expect(retries).toEqual([
      {
        kind: "retry",
        decision: {
          authority: "context-restart",
          count: 1,
          maxRetries: 3,
          delayMs: 0,
        },
      },
    ]);
    const retryIndex = calls.findIndex((call) => call.kind === "retry");
    const lastStartIndex = calls.findLastIndex((call) => call.kind === "start");
    expect(retryIndex).toBeGreaterThan(-1);
    expect(retryIndex).toBeLessThan(lastStartIndex);
  });

  it("records the tool-repair attempt and executes the repaired call", async () => {
    const { recorder, calls } = makeStore();
    const execute = makeProbeExecute();
    const doStream = vi.fn(async () => toolCallStream('{"target":12345}'));
    const doGenerate = vi.fn(async () => generated('{"target":"repaired"}'));
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream,
      doGenerate,
    });

    await runWithInferenceRecorder(recorder, async () => {
      const response = streamResponse({
        prompt: "probe the target",
        model: MODEL,
        silent: true,
        sessionId: "ses_recorded",
        tools: probeTool(execute),
      });
      await drain(response);
    });

    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute.mock.calls[0]?.[0]).toEqual({ target: "repaired" });
    const starts = calls
      .filter((call) => call.kind === "start")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    expect(
      starts.filter((attempt) => attempt.operationKind === "tool.repair"),
    ).toHaveLength(1);
  });

  it("surfaces the original critical error after a prior SDK retry", async () => {
    // First dispatch reaches the provider and fails retryably; the SDK
    // retries, and the retried attempt's pre-dispatch write fails — the
    // consumer receives the original critical error, not the SDK wrapper.
    const { recorder, calls } = makeStore({
      start: new Error("model store unreachable"),
      startOnCall: 2,
    });
    const doStream = vi
      .fn()
      .mockRejectedValueOnce(
        new APICallError({
          message: "429 too many requests",
          url: "https://provider.test/v1",
          requestBodyValues: {},
          statusCode: 429,
          isRetryable: true,
        }),
      )
      .mockImplementationOnce(async () => textStream());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    const error = await runWithInferenceRecorder(recorder, async () => {
      const response = streamResponse({
        prompt: "retry then fail",
        model: MODEL,
        silent: true,
        sessionId: "ses_recorded",
      });
      await drain(response);
    }).then(
      () => {
        throw new Error("expected the run to fail");
      },
      (cause: unknown) => cause,
    );

    expect(error).toBeInstanceOf(RunPersistenceError);
    expect(RetryError.isInstance(error)).toBe(false);
    // Exactly one provider call: the blocked attempt was the retried one.
    expect(doStream).toHaveBeenCalledTimes(1);
    const starts = calls
      .filter((call) => call.kind === "start")
      .map((call) => (call as { attempt: InferenceAttempt }).attempt);
    expect(starts).toHaveLength(2);
    expect(starts[1].idempotencyKey).toBe(starts[0].idempotencyKey);
    expect(starts[1].lineage.sequence).toBe(2);
    // The latch stops the run: no Apex retry is scheduled afterwards.
    expect(calls.filter((call) => call.kind === "retry")).toHaveLength(0);
    await expect(recorder.flush()).rejects.toThrow(RunPersistenceError);
  });
});
