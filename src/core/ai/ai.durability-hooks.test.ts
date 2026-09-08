import type {
  LanguageModelMiddleware,
  StreamTextOnStepFinishCallback,
  ToolSet,
} from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

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
    generateText: vi.fn(),
    wrapLanguageModel: vi.fn(() => wrappedModel),
    getProviderModel: vi.fn(() => baseModel),
  };
});

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return {
    ...actual,
    streamText: mocks.streamText,
    generateText: mocks.generateText,
    wrapLanguageModel: mocks.wrapLanguageModel,
  };
});

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return { ...actual, getProviderModel: mocks.getProviderModel };
});

const { generateObjectResponse, onUsage, runWithStepContext, streamResponse } =
  await import("./ai");

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

function stepWithCache(
  inputTokens: number,
  outputTokens: number,
  cacheReadTokens: number,
  cacheWriteTokens: number,
) {
  return {
    usage: {
      inputTokens,
      outputTokens,
      totalTokens: inputTokens + outputTokens,
      inputTokenDetails: { cacheReadTokens, cacheWriteTokens },
    },
    providerMetadata: undefined,
  } as unknown as Parameters<StreamTextOnStepFinishCallback<ToolSet>>[0];
}

function objectResult(
  inputTokens: number,
  outputTokens: number,
  cacheReadTokens = 0,
  cacheWriteTokens = 0,
) {
  return {
    output: { result: "ok" },
    usage: {
      inputTokens,
      outputTokens,
      ...(cacheReadTokens > 0 || cacheWriteTokens > 0
        ? { inputTokenDetails: { cacheReadTokens, cacheWriteTokens } }
        : {}),
    },
    providerMetadata: undefined,
  };
}

const objectSchema = z.object({ result: z.string() });

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
      // Both the global callback and the per-run recorder receive the same
      // cache-aware context.
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
      expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      });
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
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      });
    });

    it("does not fire usage for zero-token steps", async () => {
      const usageRecorder = vi.fn();
      streamResponse({ model: "test-model", prompt: "hi", usageRecorder });
      await streamCall(0).onStepFinish(step(0, 0));
      expect(usageRecorder).not.toHaveBeenCalled();
    });

    it("passes the cached and uncached split to the recorder", async () => {
      const usageRecorder = vi.fn();
      streamResponse({ model: "test-model", prompt: "hi", usageRecorder });
      await streamCall(0).onStepFinish(stepWithCache(11, 7, 4, 2));
      expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
        cacheReadTokens: 4,
        cacheWriteTokens: 2,
      });
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
      expect(recorderA).toHaveBeenCalledWith("model-a", 3, 5, {
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      });
      expect(recorderB).toHaveBeenCalledWith("model-b", 13, 17, {
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      });
    });
  });
});

describe("generateObjectResponse usageRecorder", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getProviderModel.mockReturnValue(mocks.baseModel);
    mocks.generateText.mockResolvedValue(objectResult(11, 7));
  });

  afterEach(() => {
    onUsage(null);
  });

  it("falls back to the global usage callback when no recorder is set", async () => {
    const globalUsage = vi.fn();
    onUsage(globalUsage);
    await generateObjectResponse({
      model: "test-model",
      schema: objectSchema,
      prompt: "hi",
    });
    expect(globalUsage).toHaveBeenCalledOnce();
    expect(globalUsage).toHaveBeenCalledWith("test-model", 11, 7, {
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });

  it("routes usage to the per-run recorder and skips the global when set", async () => {
    const globalUsage = vi.fn();
    const usageRecorder = vi.fn();
    onUsage(globalUsage);
    await generateObjectResponse({
      model: "test-model",
      schema: objectSchema,
      prompt: "hi",
      usageRecorder,
    });
    expect(usageRecorder).toHaveBeenCalledOnce();
    expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
    expect(globalUsage).not.toHaveBeenCalled();
  });

  it("attributes usage to the active run's step context", async () => {
    const usageRecorder = vi.fn();
    await runWithStepContext({ sessionId: "ses_durable", seedStepSeq: 4 }, () =>
      generateObjectResponse({
        model: "test-model",
        schema: objectSchema,
        prompt: "hi",
        usageRecorder,
      }),
    );
    expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
      sessionId: "ses_durable",
      stepSeq: 4,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });

  it("does not fire usage for zero-token responses", async () => {
    mocks.generateText.mockResolvedValue(objectResult(0, 0));
    const usageRecorder = vi.fn();
    await generateObjectResponse({
      model: "test-model",
      schema: objectSchema,
      prompt: "hi",
      usageRecorder,
    });
    expect(usageRecorder).not.toHaveBeenCalled();
  });

  it("passes the cached and uncached split to the recorder", async () => {
    mocks.generateText.mockResolvedValue(objectResult(11, 7, 4, 2));
    const usageRecorder = vi.fn();
    await generateObjectResponse({
      model: "test-model",
      schema: objectSchema,
      prompt: "hi",
      usageRecorder,
    });
    expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
      cacheReadTokens: 4,
      cacheWriteTokens: 2,
    });
  });
});

describe("usage sink resolution", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getProviderModel.mockReturnValue(mocks.baseModel);
    mocks.wrapLanguageModel.mockReturnValue(mocks.wrappedModel);
    mocks.streamText.mockImplementation(emptyStreamResult);
    mocks.generateText.mockResolvedValue(objectResult(11, 7));
  });

  afterEach(() => {
    onUsage(null);
  });

  it("uses the ALS run sink when no recorder is set", async () => {
    const usageSink = vi.fn();
    streamResponse({ model: "test-model", prompt: "hi" });
    await runWithStepContext({ sessionId: "ses_als", usageSink }, () =>
      Promise.resolve(streamCall(0).onStepFinish(step(11, 7))),
    );
    expect(usageSink).toHaveBeenCalledWith("test-model", 11, 7, {
      sessionId: "ses_als",
      stepSeq: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });

  it("lets an explicit recorder win over the ALS sink and ambient callback", async () => {
    const ambient = vi.fn();
    const usageSink = vi.fn();
    const usageRecorder = vi.fn();
    onUsage(ambient);
    streamResponse({ model: "test-model", prompt: "hi", usageRecorder });
    await runWithStepContext({ sessionId: "ses_als", usageSink }, () =>
      Promise.resolve(streamCall(0).onStepFinish(step(11, 7))),
    );
    expect(usageRecorder).toHaveBeenCalledOnce();
    expect(usageSink).not.toHaveBeenCalled();
    expect(ambient).not.toHaveBeenCalled();
  });

  it("falls back to onUsage outside any run context", async () => {
    const ambient = vi.fn();
    onUsage(ambient);
    streamResponse({ model: "test-model", prompt: "hi" });
    await streamCall(0).onStepFinish(step(11, 7));
    expect(ambient).toHaveBeenCalledOnce();
  });

  it("keeps concurrent ALS sinks isolated", async () => {
    const sinkA = vi.fn();
    const sinkB = vi.fn();
    streamResponse({ model: "model-a", prompt: "a" });
    streamResponse({ model: "model-b", prompt: "b" });
    await Promise.all([
      runWithStepContext({ sessionId: "ses_a", usageSink: sinkA }, () =>
        Promise.resolve(streamCall(0).onStepFinish(step(3, 5))),
      ),
      runWithStepContext({ sessionId: "ses_b", usageSink: sinkB }, () =>
        Promise.resolve(streamCall(1).onStepFinish(step(13, 17))),
      ),
    ]);
    expect(sinkA).toHaveBeenCalledWith("model-a", 3, 5, {
      sessionId: "ses_a",
      stepSeq: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
    expect(sinkB).toHaveBeenCalledWith("model-b", 13, 17, {
      sessionId: "ses_b",
      stepSeq: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });

  it("generateObjectResponse records via ALS without opts.usageRecorder", async () => {
    const usageSink = vi.fn();
    await runWithStepContext(
      { sessionId: "ses_als", seedStepSeq: 2, usageSink },
      () =>
        generateObjectResponse({
          model: "test-model",
          schema: objectSchema,
          prompt: "hi",
        }),
    );
    expect(usageSink).toHaveBeenCalledWith("test-model", 11, 7, {
      sessionId: "ses_als",
      stepSeq: 2,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });

  it("inherits the ALS sink across nested runWithStepContext calls", async () => {
    const usageSink = vi.fn();
    streamResponse({ model: "test-model", prompt: "hi" });
    await runWithStepContext({ sessionId: "ses_outer", usageSink }, () =>
      runWithStepContext({ sessionId: "ses_inner", seedStepSeq: 9 }, () =>
        Promise.resolve(streamCall(0).onStepFinish(step(11, 7))),
      ),
    );
    expect(usageSink).toHaveBeenCalledWith("test-model", 11, 7, {
      sessionId: "ses_inner",
      stepSeq: 9,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });
});
