import type {
  LanguageModelMiddleware,
  StreamTextOnStepFinishCallback,
  ToolSet,
} from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const baseModel = {
    specificationVersion: "v3" as const,
    provider: "test",
    modelId: "base",
    supportedUrls: {},
    doGenerate: vi.fn(),
    doStream: vi.fn(),
  };
  const wrappedModel = { ...baseModel, modelId: "wrapped" };
  return {
    baseModel,
    wrappedModel,
    streamText: vi.fn(),
    wrapLanguageModel: vi.fn(() => wrappedModel),
    getProviderModel: vi.fn(() => baseModel),
  };
});

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return {
    ...actual,
    streamText: mocks.streamText,
    wrapLanguageModel: mocks.wrapLanguageModel,
  };
});

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return { ...actual, getProviderModel: mocks.getProviderModel };
});

const { onUsage, runWithStepContext, streamResponse } = await import("./ai");

function emptyStreamResult() {
  return {
    fullStream: (async function* () {
      yield* [];
    })(),
    response: Promise.resolve({ messages: [] }),
  };
}

function step(inputTokens: number, outputTokens: number) {
  return {
    usage: {
      inputTokens,
      outputTokens,
      totalTokens: inputTokens + outputTokens,
    },
    providerMetadata: undefined,
  } as unknown as Parameters<StreamTextOnStepFinishCallback<ToolSet>>[0];
}

function streamCall(index: number) {
  const call = mocks.streamText.mock.calls[index];
  if (!call) throw new Error(`Missing streamText call ${index}`);
  return call[0] as {
    model: unknown;
    maxRetries: number;
    onStepFinish: StreamTextOnStepFinishCallback<ToolSet>;
  };
}

describe("streamResponse durability hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getProviderModel.mockReturnValue(mocks.baseModel);
    mocks.wrapLanguageModel.mockReturnValue(mocks.wrappedModel);
    mocks.streamText.mockImplementation(emptyStreamResult);
  });

  afterEach(() => {
    onUsage(null);
  });

  describe("languageModelMiddleware", () => {
    it("passes the raw model through and never wraps when unset", () => {
      streamResponse({ model: "test-model", prompt: "hi" });
      expect(mocks.wrapLanguageModel).not.toHaveBeenCalled();
      expect(streamCall(0).model).toBe(mocks.baseModel);
      expect(streamCall(0).maxRetries).toBe(3);
    });

    it("wraps the model with the middleware when set", () => {
      const middleware: LanguageModelMiddleware = {
        specificationVersion: "v3",
      };
      streamResponse({
        model: "test-model",
        prompt: "hi",
        languageModelMiddleware: middleware,
      });
      expect(mocks.wrapLanguageModel).toHaveBeenCalledOnce();
      expect(mocks.wrapLanguageModel).toHaveBeenCalledWith({
        model: mocks.baseModel,
        middleware,
      });
      expect(streamCall(0).model).toBe(mocks.wrappedModel);
    });
  });

  describe("usageRecorder", () => {
    it("falls back to the global usage callback when no recorder is set", async () => {
      const globalUsage = vi.fn();
      onUsage(globalUsage);
      streamResponse({ model: "test-model", prompt: "hi" });
      await streamCall(0).onStepFinish(step(11, 7));
      expect(globalUsage).toHaveBeenCalledOnce();
      // The global callback keeps its cache-aware context; only the per-run
      // usageRecorder gets the plain run step context.
      expect(globalUsage).toHaveBeenCalledWith("test-model", 11, 7, {
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      });
    });

    it("routes usage to the per-run recorder and skips the global when set", async () => {
      const globalUsage = vi.fn();
      const usageRecorder = vi.fn();
      onUsage(globalUsage);
      streamResponse({ model: "test-model", prompt: "hi", usageRecorder });
      await streamCall(0).onStepFinish(step(11, 7));
      expect(usageRecorder).toHaveBeenCalledOnce();
      expect(usageRecorder).toHaveBeenCalledWith(
        "test-model",
        11,
        7,
        undefined,
      );
      expect(globalUsage).not.toHaveBeenCalled();
    });

    it("attributes usage to the active run's step context", async () => {
      const usageRecorder = vi.fn();
      streamResponse({ model: "test-model", prompt: "hi", usageRecorder });
      await runWithStepContext(
        { sessionId: "ses_durable", seedStepSeq: 4 },
        () => Promise.resolve(streamCall(0).onStepFinish(step(11, 7))),
      );
      expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
        sessionId: "ses_durable",
        stepSeq: 4,
      });
    });

    it("does not fire usage for zero-token steps", async () => {
      const usageRecorder = vi.fn();
      streamResponse({ model: "test-model", prompt: "hi", usageRecorder });
      await streamCall(0).onStepFinish(step(0, 0));
      expect(usageRecorder).not.toHaveBeenCalled();
    });

    it("keeps concurrent recorders scoped to their own model loops", async () => {
      const recorderA = vi.fn();
      const recorderB = vi.fn();
      streamResponse({
        model: "model-a",
        prompt: "a",
        usageRecorder: recorderA,
      });
      streamResponse({
        model: "model-b",
        prompt: "b",
        usageRecorder: recorderB,
      });
      await Promise.all([
        streamCall(0).onStepFinish(step(3, 5)),
        streamCall(1).onStepFinish(step(13, 17)),
      ]);
      expect(recorderA).toHaveBeenCalledWith("model-a", 3, 5, undefined);
      expect(recorderB).toHaveBeenCalledWith("model-b", 13, 17, undefined);
    });
  });
});
