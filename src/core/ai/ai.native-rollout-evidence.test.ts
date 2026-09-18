import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
} from "@ai-sdk/provider";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
  };
});

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return { ...actual, streamText: mocks.streamText };
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

const { streamResponse } = await import("./ai");
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
});
