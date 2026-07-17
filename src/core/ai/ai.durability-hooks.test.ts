import type {
  LanguageModelMiddleware,
  StreamTextOnStepFinishCallback,
  ToolSet,
} from "ai";
import { beforeEach, describe, expect, it, vi } from "vitest";
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
  const wrappedModel = {
    ...baseModel,
    modelId: "wrapped",
  };

  return {
    baseModel,
    wrappedModel,
    generateText: vi.fn(),
    getProviderModel: vi.fn(() => baseModel),
    streamText: vi.fn(),
    wrapLanguageModel: vi.fn(() => wrappedModel),
  };
});

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return {
    ...actual,
    generateText: mocks.generateText,
    streamText: mocks.streamText,
    wrapLanguageModel: mocks.wrapLanguageModel,
  };
});

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return {
    ...actual,
    getProviderModel: mocks.getProviderModel,
  };
});

const { runWithStepContext, streamResponse } = await import("./ai");
const { createSummarizationStream } = await import("./utils");

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
      inputTokenDetails: {},
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
    experimental_repairToolCall: (input: {
      toolCall: { toolCallId: string; toolName: string; input: string };
      inputSchema: (input: { toolName: string }) => unknown;
      tools: Record<string, { inputSchema: unknown }>;
      error: Error;
    }) => Promise<unknown>;
  };
}

describe("streamResponse durability hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getProviderModel.mockReturnValue(mocks.baseModel);
    mocks.streamText.mockImplementation(emptyStreamResult);
    mocks.wrapLanguageModel.mockReturnValue(mocks.wrappedModel);
    mocks.generateText.mockResolvedValue({
      output: { repaired: true },
      usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
    });
  });

  it("preserves the unwrapped model and three AI SDK retries by default", () => {
    streamResponse({ model: "test-model", prompt: "test" });

    expect(mocks.wrapLanguageModel).not.toHaveBeenCalled();
    expect(streamCall(0).model).toBe(mocks.baseModel);
    expect(streamCall(0).maxRetries).toBe(3);
  });

  it("applies middleware and the retry override to stream and repair calls", async () => {
    const middleware: LanguageModelMiddleware = {
      specificationVersion: "v3",
    };

    streamResponse({
      model: "test-model",
      prompt: "test",
      languageModelMiddleware: middleware,
      maxRetries: 0,
    });

    expect(mocks.wrapLanguageModel).toHaveBeenCalledOnce();
    expect(mocks.wrapLanguageModel).toHaveBeenCalledWith({
      model: mocks.baseModel,
      middleware,
    });
    expect(streamCall(0).model).toBe(mocks.wrappedModel);
    expect(streamCall(0).maxRetries).toBe(0);

    const toolSchema = z.object({ repaired: z.boolean() });
    await streamCall(0).experimental_repairToolCall({
      toolCall: {
        toolCallId: "call-1",
        toolName: "probe",
        input: "{}",
      },
      inputSchema: () => ({ type: "object" }),
      tools: { probe: { inputSchema: toolSchema } },
      error: new Error("invalid input"),
    });

    expect(mocks.generateText).toHaveBeenCalledOnce();
    const generateCall = mocks.generateText.mock.calls[0];
    if (!generateCall) throw new Error("Missing generateText call");
    expect(generateCall[0]).toMatchObject({
      model: mocks.wrappedModel,
      maxRetries: 0,
    });
  });

  it("awaits repair usage and propagates recorder failure", async () => {
    let rejectRecorder!: (error: Error) => void;
    const usageRecorder = vi.fn(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectRecorder = reject;
        }),
    );
    streamResponse({
      model: "test-model",
      prompt: "test",
      usageRecorder,
    });

    const toolSchema = z.object({ repaired: z.boolean() });
    let settled = false;
    const failure = new Error("usage persistence failed");
    const repair = streamCall(0)
      .experimental_repairToolCall({
        toolCall: {
          toolCallId: "call-1",
          toolName: "probe",
          input: "{}",
        },
        inputSchema: () => ({ type: "object" }),
        tools: { probe: { inputSchema: toolSchema } },
        error: new Error("invalid input"),
      })
      .then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      )
      .finally(() => {
        settled = true;
      });

    await vi.waitFor(() => {
      expect(usageRecorder).toHaveBeenCalledOnce();
    });
    expect(settled).toBe(false);

    rejectRecorder(failure);
    await expect(repair).resolves.toEqual({ error: failure });
    expect(settled).toBe(true);
  });

  it("awaits the per-call usage recorder with exact step attribution", async () => {
    let release!: () => void;
    const usageRecorder = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );

    streamResponse({
      model: "test-model",
      prompt: "test",
      usageRecorder,
      onCacheMetrics: vi.fn(),
    });

    let settled = false;
    const recording = runWithStepContext(
      { sessionId: "ses_durable", seedStepSeq: 4 },
      () => Promise.resolve(streamCall(0).onStepFinish(step(11, 7))),
    ).then(() => {
      settled = true;
    });

    await Promise.resolve();
    expect(settled).toBe(false);
    expect(usageRecorder).toHaveBeenCalledOnce();
    expect(usageRecorder).toHaveBeenCalledWith("test-model", 11, 7, {
      sessionId: "ses_durable",
      stepSeq: 4,
    });

    release();
    await recording;
    expect(settled).toBe(true);
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

    expect(recorderA).toHaveBeenCalledOnce();
    expect(recorderA).toHaveBeenCalledWith("model-a", 3, 5, undefined);
    expect(recorderB).toHaveBeenCalledOnce();
    expect(recorderB).toHaveBeenCalledWith("model-b", 13, 17, undefined);
  });

  it("applies retry and awaited usage hooks to summarization calls", async () => {
    let release!: () => void;
    const usageRecorder = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    mocks.generateText.mockResolvedValue({
      text: "summary",
      usage: { inputTokens: 23, outputTokens: 29, totalTokens: 52 },
    });

    const stream = createSummarizationStream(
      [{ role: "user", content: "large conversation" }],
      {
        model: "test-model",
        prompt: "continue",
        maxRetries: 0,
        usageRecorder,
      },
      mocks.wrappedModel,
    );
    let settled = false;
    const consuming = (async () => {
      for await (const chunk of stream.fullStream) void chunk;
      settled = true;
    })();

    await vi.waitFor(() => {
      expect(usageRecorder).toHaveBeenCalledOnce();
    });
    expect(settled).toBe(false);
    const generateCall = mocks.generateText.mock.calls[0];
    if (!generateCall)
      throw new Error("Missing summarization generateText call");
    expect(generateCall[0]).toMatchObject({
      model: mocks.wrappedModel,
      maxRetries: 0,
    });
    expect(usageRecorder).toHaveBeenCalledWith("test-model", 23, 29, undefined);

    release();
    await consuming;
    expect(settled).toBe(true);
  });
});
