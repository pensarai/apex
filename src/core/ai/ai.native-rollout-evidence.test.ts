import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
} from "@ai-sdk/provider";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

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
    streamText: vi.fn((_input: { model: LanguageModelV3 }) => ({
      fullStream: (async function* () {
        yield* [];
      })(),
      response: Promise.resolve({ messages: [] }),
    })),
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
});
