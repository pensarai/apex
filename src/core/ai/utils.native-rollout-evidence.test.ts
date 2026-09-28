import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
} from "@ai-sdk/provider";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const state: {
    callOptions?: LanguageModelV3CallOptions;
    resumedModel?: LanguageModelV3;
    resumedCall?: Promise<LanguageModelV3GenerateResult>;
  } = {};
  return {
    state,
    generateText: vi.fn(async (input: { model: LanguageModelV3 }) => {
      if (!state.callOptions) throw new Error("missing fixture call options");
      await input.model.doGenerate(state.callOptions);
      return {
        text: "bounded summary",
        usage: { inputTokens: 2, outputTokens: 1, totalTokens: 3 },
        providerMetadata: undefined,
      };
    }),
    streamResponse: vi.fn(() => {
      if (!state.callOptions || !state.resumedModel) {
        throw new Error("missing resumed-call fixture");
      }
      state.resumedCall = Promise.resolve(
        state.resumedModel.doGenerate(state.callOptions),
      );
      return {
        fullStream: (async function* () {
          await state.resumedCall;
          yield* [];
        })(),
      };
    }),
  };
});

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return { ...actual, generateText: mocks.generateText };
});

vi.mock("./ai", () => ({
  buildOpenRouterProviderOptions: vi.fn(() => undefined),
  streamResponse: mocks.streamResponse,
}));

const { createSummarizationStream } = await import("./utils");
const { createNativeRolloutEvidenceCapture, withNativeRolloutEvidenceModel } =
  await import("./native-rollout-evidence");

const callOptions = {
  prompt: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
} as LanguageModelV3CallOptions;

function generated(): LanguageModelV3GenerateResult {
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

function model(): LanguageModelV3 {
  return {
    specificationVersion: "v3",
    provider: "openai.chat",
    modelId: "provider-model",
    supportedUrls: {},
    doGenerate: vi.fn(async () => generated()),
    doStream: vi.fn(),
  };
}

describe("summarization native rollout evidence boundary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.state.callOptions = callOptions;
    mocks.state.resumedModel = undefined;
    mocks.state.resumedCall = undefined;
  });

  it("labels only the summary inference and restores the resumed agent label", async () => {
    const envelopes: Array<{ operationKind: string }> = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-summary-boundary",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
        sessionId: "ses_summary_boundary",
      });
      mocks.state.resumedModel = wrapped;
      const stream = createSummarizationStream(
        [{ role: "user", content: "history" }],
        {
          model: "openai/gpt-5",
          prompt: "resume",
          sessionId: "ses_summary_boundary",
        },
        wrapped,
      );
      for await (const _part of stream.fullStream) {
        // Draining waits for both the summarization and resumed inference.
      }
    });
    await capture.flush();

    expect(mocks.generateText).toHaveBeenCalledOnce();
    expect(mocks.streamResponse).toHaveBeenCalledOnce();
    expect(envelopes.map((entry) => entry.operationKind)).toEqual([
      "context.summarize",
      "agent.stream",
    ]);
  });
});
