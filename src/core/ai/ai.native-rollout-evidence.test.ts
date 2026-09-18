import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

interface MockStreamTextResult {
  fullStream: AsyncIterable<unknown>;
  response: Promise<{ messages: unknown[] }>;
}

const mocks = vi.hoisted(() => {
  const baseModel = {
    specificationVersion: "v3" as const,
    provider: "openai.chat",
    modelId: "provider-model",
    supportedUrls: {},
    doGenerate: vi.fn(),
    doStream: vi.fn(),
  } satisfies LanguageModelV3;
  return {
    baseModel,
    getProviderModel: vi.fn(() => baseModel),
    streamText: vi.fn(
      (_input: { model: LanguageModelV3 }): MockStreamTextResult => ({
        fullStream: (async function* () {
          yield* [];
        })(),
        response: Promise.resolve({ messages: [] }),
      }),
    ),
    generateText: vi.fn(),
  };
});

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return {
    ...actual,
    generateText: mocks.generateText,
    streamText: mocks.streamText,
  };
});

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return { ...actual, getProviderModel: mocks.getProviderModel };
});

vi.mock("../observability", async () => {
  const actual =
    await vi.importActual<typeof import("../observability")>(
      "../observability",
    );
  return {
    ...actual,
    withModelCallDiagnostics: (model: LanguageModelV3) => model,
  };
});

const { generateObjectResponse, streamResponse } = await import("./ai");
const { createNativeRolloutEvidenceCapture } = await import(
  "./native-rollout-evidence"
);

const callOptions = {
  prompt: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
} as LanguageModelV3CallOptions;

function result(): LanguageModelV3GenerateResult {
  return {
    content: [{ type: "text", text: "world" }],
    finishReason: { unified: "stop", raw: "stop" },
    usage: {
      inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
      outputTokens: { total: 1, text: 1, reasoning: 0 },
    },
    request: { body: { messages: ["hello"] } },
    response: { modelId: "effective-model" },
    warnings: [],
  };
}

function streamResult(): Awaited<ReturnType<LanguageModelV3["doStream"]>> {
  return {
    stream: new ReadableStream<LanguageModelV3StreamPart>({
      start(controller) {
        controller.enqueue({ type: "stream-start", warnings: [] });
        controller.enqueue({ type: "text-start", id: "text-1" });
        controller.enqueue({
          type: "text-delta",
          id: "text-1",
          delta: "done",
        });
        controller.enqueue({ type: "text-end", id: "text-1" });
        controller.enqueue({
          type: "finish",
          finishReason: { unified: "stop", raw: "stop" },
          usage: result().usage,
        });
        controller.close();
      },
    }),
    request: { body: { messages: ["hello"] } },
  };
}

describe("ai native rollout evidence boundary", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getProviderModel.mockReturnValue(mocks.baseModel);
    mocks.baseModel.doGenerate.mockResolvedValue(result());
  });

  it("passes a run-scoped passive wrapper to streamText", async () => {
    const envelopes: unknown[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-ai-boundary",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      streamResponse({
        model: "test-model",
        prompt: "hello",
        sessionId: "ses_ai_boundary",
      });
      const input = mocks.streamText.mock.calls[0]?.[0];
      const wrapped = input?.model as LanguageModelV3;
      expect(wrapped).not.toBe(mocks.baseModel);
      await wrapped.doGenerate(callOptions);
    });
    await capture.flush();

    expect(mocks.baseModel.doGenerate).toHaveBeenCalledWith(callOptions);
    expect(envelopes).toEqual([
      expect.objectContaining({
        runId: "run-ai-boundary",
        sessionId: "ses_ai_boundary",
        operationKind: "agent.stream",
        requested: expect.objectContaining({ modelId: "test-model" }),
        effective: expect.objectContaining({ modelId: "effective-model" }),
      }),
    ]);
  });

  it("links structured generation retries within one physical operation", async () => {
    vi.useFakeTimers();
    const envelopes: Array<{
      attempt: {
        attemptId: string;
        idempotencyKey: string;
        lifecycle: string;
        previousAttemptId?: string;
        rootAttemptId: string;
        sequence: number;
      };
      turnId: string;
    }> = [];
    const attempts: Array<{
      attemptId: string;
      idempotencyKey: string;
      lifecycle: string;
    }> = [];
    mocks.baseModel.doGenerate
      .mockRejectedValueOnce(
        Object.assign(new Error("rate limited fixture"), { statusCode: 429 }),
      )
      .mockResolvedValueOnce(result());
    mocks.generateText.mockImplementation(
      async (input: { model: LanguageModelV3 }) => {
        const generated = await input.model.doGenerate(callOptions);
        return {
          output: { answer: "done" },
          providerMetadata: generated.providerMetadata,
          usage: generated.usage,
        };
      },
    );
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-structured-retry",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
      attemptSink: {
        write: (attempt) => {
          attempts.push(attempt);
        },
      },
    });

    const response = capture.run(() =>
      generateObjectResponse({
        model: "test-model",
        schema: z.object({ answer: z.string() }),
        prompt: "return an answer",
        sessionId: "ses_structured_retry",
      }),
    );
    await vi.waitFor(() =>
      expect(mocks.baseModel.doGenerate).toHaveBeenCalledTimes(1),
    );
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(response).resolves.toEqual({ answer: "done" });
    await capture.flush();
    expect(envelopes.map((entry) => entry.attempt.lifecycle)).toEqual([
      "retried",
      "completed",
    ]);
    expect(envelopes[1]?.turnId).toBe(envelopes[0]?.turnId);
    expect(envelopes[1]?.attempt).toMatchObject({
      idempotencyKey: envelopes[0]?.attempt.idempotencyKey,
      previousAttemptId: envelopes[0]?.attempt.attemptId,
      rootAttemptId: envelopes[0]?.attempt.attemptId,
      sequence: 2,
    });
    expect(attempts.map((attempt) => attempt.lifecycle)).toEqual([
      "started",
      "retried",
      "started",
      "completed",
    ]);
  });

  it("links streamed rate-limit recovery within one physical operation", async () => {
    vi.useFakeTimers();
    const envelopes: Array<{
      attempt: {
        attemptId: string;
        idempotencyKey: string;
        lifecycle: string;
        previousAttemptId?: string;
        rootAttemptId: string;
        sequence: number;
      };
      turnId: string;
    }> = [];
    mocks.baseModel.doStream
      .mockRejectedValueOnce(
        Object.assign(new Error("stream rate limited fixture"), {
          statusCode: 429,
        }),
      )
      .mockResolvedValueOnce(streamResult());
    mocks.streamText.mockImplementation((input: { model: LanguageModelV3 }) => {
      const streamed = input.model.doStream(callOptions);
      return {
        fullStream: (async function* () {
          const reader = (await streamed).stream.getReader();
          for (;;) {
            const part = await reader.read();
            if (part.done) break;
          }
          yield { type: "text-delta", text: "done" };
        })(),
        response: Promise.resolve({ messages: [] }),
      };
    });
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-stream-retry",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    const stream = capture.run(() =>
      streamResponse({
        model: "test-model",
        prompt: "hello",
        sessionId: "ses_stream_retry",
      }),
    );
    const chunks: unknown[] = [];
    const consumed = (async () => {
      for await (const chunk of stream.fullStream) chunks.push(chunk);
    })();
    await vi.waitFor(() =>
      expect(mocks.baseModel.doStream).toHaveBeenCalledTimes(1),
    );
    await vi.advanceTimersByTimeAsync(1_000);
    await consumed;
    await capture.flush();

    expect(chunks).toEqual([{ type: "text-delta", text: "done" }]);
    expect(envelopes.map((entry) => entry.attempt.lifecycle)).toEqual([
      "retried",
      "completed",
    ]);
    expect(envelopes[1]?.turnId).toBe(envelopes[0]?.turnId);
    expect(envelopes[1]?.attempt).toMatchObject({
      idempotencyKey: envelopes[0]?.attempt.idempotencyKey,
      previousAttemptId: envelopes[0]?.attempt.attemptId,
      rootAttemptId: envelopes[0]?.attempt.attemptId,
      sequence: 2,
    });
  });

  it("keeps separate successful stream invocations as distinct turns", async () => {
    const envelopes: Array<{ turnId: string }> = [];
    mocks.streamText.mockImplementation((input: { model: LanguageModelV3 }) => {
      const response = Promise.resolve(
        input.model.doGenerate(callOptions),
      ).then(() => ({ messages: [] }));
      return {
        fullStream: (async function* () {
          await response;
          yield* [];
        })(),
        response,
      };
    });
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-stream-continuations",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      for (const prompt of ["first", "second"]) {
        const stream = streamResponse({
          model: "test-model",
          prompt,
          sessionId: "ses_stream_continuations",
        });
        for await (const _chunk of stream.fullStream) {
          // This fixture emits no consumer-visible parts.
        }
      }
    });
    await capture.flush();

    expect(envelopes).toHaveLength(2);
    expect(envelopes[0]?.turnId).not.toBe(envelopes[1]?.turnId);
  });
});
