import type {
  LanguageModelV4,
  LanguageModelV4CallOptions,
  LanguageModelV4GenerateResult,
  LanguageModelV4StreamResult,
} from "@ai-sdk/provider";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const state: {
    callOptions?: LanguageModelV4CallOptions;
    resumedModel?: LanguageModelV4;
    resumedCall?: Promise<LanguageModelV4GenerateResult>;
  } = {};
  return {
    state,
    streamText: vi.fn((input: { model: LanguageModelV4 }) => {
      if (!state.callOptions) throw new Error("missing fixture call options");
      const called = input.model.doStream(state.callOptions);
      return {
        text: called.then(() => "bounded summary"),
        usage: called.then(() => ({
          inputTokens: 2,
          outputTokens: 1,
          totalTokens: 3,
        })),
        finishReason: called.then(() => "stop"),
        providerMetadata: called.then(() => undefined),
        toolCalls: called.then(() => []),
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
  return { ...actual, streamText: mocks.streamText };
});

vi.mock("./ai", () => ({
  buildOpenRouterProviderOptions: vi.fn(() => undefined),
  buildReasoningProviderOptions: vi.fn(() => undefined),
  mergeProviderOptions: vi.fn(() => undefined),
  recordContextRestart: vi.fn(async () => {}),
  resumeMessagesWithPinned: vi.fn(() => undefined),
  streamResponse: mocks.streamResponse,
}));

const { createSummarizationStream } = await import("./utils");
const { createNativeRolloutEvidenceCapture, withNativeRolloutEvidenceModel } =
  await import("./native-rollout-evidence");

const callOptions = {
  prompt: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
} as LanguageModelV4CallOptions;

function generated(): LanguageModelV4GenerateResult {
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

function streamed(): LanguageModelV4StreamResult {
  return { stream: new ReadableStream({ start: (c) => c.close() }) };
}

function model(): LanguageModelV4 {
  return {
    specificationVersion: "v4",
    provider: "openai.chat",
    modelId: "provider-model",
    supportedUrls: {},
    doGenerate: vi.fn(async () => generated()),
    doStream: vi.fn(async () => streamed()),
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

    expect(mocks.streamText).toHaveBeenCalledOnce();
    expect(mocks.streamResponse).toHaveBeenCalledOnce();
    expect(envelopes.map((entry) => entry.operationKind)).toEqual([
      "context.summarize",
      "agent.stream",
    ]);
  });
});
