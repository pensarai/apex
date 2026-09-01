// Tests for the cache-aware usage callback (T6): every usage report carries
// cache-read and cache-write counters (zero when the provider supplies
// none), inputTokens stays inclusive of cached tokens, one normalization
// feeds both onCacheMetrics and the usage callback, and async callbacks are
// awaited before the step settles.

import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { generateObjectResponse, normalizeStepUsage, onUsage } from "./ai";

// getProviderModel is patched so no provider keys are needed — the mock
// model serves protocol parts directly.
const mockState: { model: MockLanguageModelV3 | null } = { model: null };
vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return {
    ...actual,
    getProviderModel: () => {
      if (!mockState.model) throw new Error("mock model not set");
      return mockState.model;
    },
  };
});

// Imported AFTER vi.mock so streamResponse/generateObjectResponse closures
// pick up the stubbed getProviderModel.
const { streamResponse } = await import("./ai");

// ---------------------------------------------------------------------------
// Mock fixtures
// ---------------------------------------------------------------------------

interface StepUsageSpec {
  usage: {
    inputTokens: number;
    outputTokens: number;
    inputTokenDetails?: {
      cacheReadTokens?: number;
      cacheWriteTokens?: number;
    };
  };
  providerMetadata?: Record<string, unknown>;
}

function textStepChunks(spec: StepUsageSpec): Array<Record<string, unknown>> {
  // The v3 protocol carries nested usage; the SDK normalizes it into the
  // inclusive inputTokens + inputTokenDetails the normalizer reads.
  const cacheRead = spec.usage.inputTokenDetails?.cacheReadTokens ?? 0;
  const cacheWrite = spec.usage.inputTokenDetails?.cacheWriteTokens ?? 0;
  return [
    { type: "stream-start", warnings: [] },
    { type: "text-start", id: "txt-1" },
    { type: "text-delta", id: "txt-1", delta: "hi" },
    { type: "text-end", id: "txt-1" },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage: {
        inputTokens: {
          total: spec.usage.inputTokens,
          noCache: spec.usage.inputTokens - cacheRead - cacheWrite,
          cacheRead,
          cacheWrite,
        },
        outputTokens: { total: spec.usage.outputTokens },
      },
      ...(spec.providerMetadata
        ? { providerMetadata: spec.providerMetadata }
        : {}),
    },
  ];
}

function oneStepModel(spec: StepUsageSpec): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: textStepChunks(
          spec,
        ) as unknown as Array<LanguageModelV3StreamPart>,
      }),
    }),
  });
}

type UsageCall = {
  modelId: string;
  inputTokens: number;
  outputTokens: number;
  context: {
    sessionId?: string;
    stepSeq?: number;
    cacheReadTokens: number;
    cacheWriteTokens: number;
  };
};

function setupUsageCallback(): UsageCall[] {
  const calls: UsageCall[] = [];
  onUsage((modelId, inputTokens, outputTokens, context) => {
    calls.push({ modelId, inputTokens, outputTokens, context });
  });
  return calls;
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    // drain
  }
}

const MODEL = "claude-haiku-4-5";

afterEach(() => {
  onUsage(null);
  mockState.model = null;
});

// ---------------------------------------------------------------------------
// streamResponse — cache counters on the usage callback
// ---------------------------------------------------------------------------

describe("usage callback cache breakdown (streamResponse)", () => {
  it("no-cache usage emits both cache fields as zero", async () => {
    mockState.model = oneStepModel({
      usage: { inputTokens: 100, outputTokens: 20 },
    });
    const calls = setupUsageCallback();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    expect(calls).toHaveLength(1);
    expect(calls[0]?.modelId).toBe(MODEL);
    expect(calls[0]?.inputTokens).toBe(100);
    expect(calls[0]?.outputTokens).toBe(20);
    expect(calls[0]?.context.cacheReadTokens).toBe(0);
    expect(calls[0]?.context.cacheWriteTokens).toBe(0);
  });

  it("cache-read usage preserves inclusive input totals", async () => {
    mockState.model = oneStepModel({
      usage: { inputTokens: 1000, outputTokens: 50 },
      providerMetadata: { anthropic: { cacheReadInputTokens: 900 } },
    });
    const calls = setupUsageCallback();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    // 900 of the 1000 input tokens were cache reads — input stays inclusive.
    expect(calls[0]?.inputTokens).toBe(1000);
    expect(calls[0]?.context.cacheReadTokens).toBe(900);
    expect(calls[0]?.context.cacheWriteTokens).toBe(0);
  });

  it("cache-write usage preserves inclusive input totals", async () => {
    mockState.model = oneStepModel({
      usage: { inputTokens: 1000, outputTokens: 50 },
      providerMetadata: { anthropic: { cacheCreationInputTokens: 400 } },
    });
    const calls = setupUsageCallback();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    expect(calls[0]?.inputTokens).toBe(1000);
    expect(calls[0]?.context.cacheReadTokens).toBe(0);
    expect(calls[0]?.context.cacheWriteTokens).toBe(400);
  });

  it("mixed read/write usage emits both buckets", async () => {
    mockState.model = oneStepModel({
      usage: { inputTokens: 1000, outputTokens: 30 },
      providerMetadata: {
        anthropic: {
          cacheReadInputTokens: 900,
          cacheCreationInputTokens: 100,
        },
      },
    });
    const calls = setupUsageCallback();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    expect(calls[0]?.context.cacheReadTokens).toBe(900);
    expect(calls[0]?.context.cacheWriteTokens).toBe(100);
    expect(calls[0]?.inputTokens).toBe(1000);
  });

  it("responses cached input is not added to input twice", async () => {
    // OpenAI-Responses-style: cached tokens arrive via the SDK's normalized
    // inputTokenDetails (no anthropic providerMetadata). The cached tokens
    // are part of the 1000 input tokens — the callback must not report 1800.
    mockState.model = oneStepModel({
      usage: {
        inputTokens: 1000,
        outputTokens: 20,
        inputTokenDetails: { cacheReadTokens: 800 },
      },
    });
    const calls = setupUsageCallback();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    expect(calls[0]?.inputTokens).toBe(1000);
    expect(calls[0]?.context.cacheReadTokens).toBe(800);
  });

  it("usage callback fires exactly once per completed model step", async () => {
    let streamCall = 0;
    mockState.model = new MockLanguageModelV3({
      doStream: async () => {
        streamCall += 1;
        if (streamCall === 1) {
          // Step 1: a tool call (usage arrives with the finish part).
          return {
            stream: simulateReadableStream({
              chunks: [
                { type: "stream-start", warnings: [] },
                { type: "tool-input-start", id: "call-1", toolName: "probe" },
                { type: "tool-input-delta", id: "call-1", delta: "{}" },
                { type: "tool-input-end", id: "call-1" },
                {
                  type: "tool-call",
                  toolCallId: "call-1",
                  toolName: "probe",
                  input: "{}",
                },
                {
                  type: "finish",
                  finishReason: { unified: "tool-calls", raw: "tool_use" },
                  usage: {
                    inputTokens: {
                      total: 100,
                      noCache: 100,
                      cacheRead: 0,
                      cacheWrite: 0,
                    },
                    outputTokens: { total: 10 },
                  },
                },
              ] as unknown as Array<LanguageModelV3StreamPart>,
            }),
          };
        }
        // Step 2: plain text finish.
        return {
          stream: simulateReadableStream({
            chunks: [
              { type: "stream-start", warnings: [] },
              { type: "text-start", id: "txt-2" },
              { type: "text-delta", id: "txt-2", delta: "done" },
              { type: "text-end", id: "txt-2" },
              {
                type: "finish",
                finishReason: { unified: "stop", raw: "stop" },
                usage: {
                  inputTokens: {
                    total: 200,
                    noCache: 200,
                    cacheRead: 0,
                    cacheWrite: 0,
                  },
                  outputTokens: { total: 5 },
                },
              },
            ] as unknown as Array<LanguageModelV3StreamPart>,
          }),
        };
      },
    });
    const calls = setupUsageCallback();

    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        tools: {
          probe: {
            description: "test tool",
            inputSchema: z.object({}),
            execute: async () => "ok",
          },
        },
        stopWhen: stepCountIs(2),
      }),
    );

    expect(calls).toHaveLength(2);
    expect(calls.map((c) => c.inputTokens)).toEqual([100, 200]);
  });

  it("a deferred async usage callback is awaited before the step settles", async () => {
    mockState.model = oneStepModel({
      usage: { inputTokens: 100, outputTokens: 10 },
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const seen: number[] = [];
    onUsage(async (_modelId, inputTokens) => {
      await gate;
      seen.push(inputTokens);
    });

    const result = streamResponse({ prompt: "hi", model: MODEL, silent: true });
    let drained = false;
    const consumed = (async () => {
      await drain(result);
      drained = true;
    })();

    await new Promise((resolve) => setTimeout(resolve, 25));
    // The step cannot settle while the usage callback is pending.
    expect(drained).toBe(false);
    expect(seen).toHaveLength(0);

    release();
    await consumed;
    expect(drained).toBe(true);
    expect(seen).toEqual([100]);
  });

  it("onCacheMetrics still receives the normalized cache metrics (session-usage path unchanged)", async () => {
    mockState.model = oneStepModel({
      usage: { inputTokens: 1000, outputTokens: 30 },
      providerMetadata: {
        anthropic: {
          cacheReadInputTokens: 900,
          cacheCreationInputTokens: 100,
        },
      },
    });
    const cacheEvents: Array<{
      cacheReadInputTokens: number;
      cacheCreationInputTokens: number;
    }> = [];

    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        onCacheMetrics: (m) => {
          cacheEvents.push(m);
        },
      }),
    );

    expect(cacheEvents).toEqual([
      { cacheReadInputTokens: 900, cacheCreationInputTokens: 100 },
    ]);
  });
});

// ---------------------------------------------------------------------------
// generateObjectResponse — same structure
// ---------------------------------------------------------------------------

describe("usage callback cache breakdown (generateObjectResponse)", () => {
  it("emits the same structure with cache from providerMetadata", async () => {
    mockState.model = new MockLanguageModelV3({
      doGenerate: async () => ({
        content: [{ type: "text", text: '{"result":"ok"}' }],
        finishReason: { unified: "stop", raw: "stop" },
        warnings: [],
        usage: {
          inputTokens: {
            total: 500,
            noCache: 100,
            cacheRead: 400,
            cacheWrite: 0,
          },
          outputTokens: { total: 40, text: undefined, reasoning: undefined },
        },
        providerMetadata: { anthropic: { cacheReadInputTokens: 400 } },
      }),
    });
    const calls = setupUsageCallback();

    const output = await generateObjectResponse({
      model: MODEL,
      schema: z.object({ result: z.string() }),
      prompt: "hi",
    });

    expect(output).toEqual({ result: "ok" });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.inputTokens).toBe(500);
    expect(calls[0]?.outputTokens).toBe(40);
    expect(calls[0]?.context.cacheReadTokens).toBe(400);
    expect(calls[0]?.context.cacheWriteTokens).toBe(0);
  });

  it("emits zero cache counters when the provider supplies none", async () => {
    mockState.model = new MockLanguageModelV3({
      doGenerate: async () => ({
        content: [{ type: "text", text: '{"result":"ok"}' }],
        finishReason: { unified: "stop", raw: "stop" },
        warnings: [],
        usage: {
          inputTokens: { total: 50, noCache: 50, cacheRead: 0, cacheWrite: 0 },
          outputTokens: { total: 5, text: undefined, reasoning: undefined },
        },
      }),
    });
    const calls = setupUsageCallback();

    await generateObjectResponse({
      model: MODEL,
      schema: z.object({ result: z.string() }),
      prompt: "hi",
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.context.cacheReadTokens).toBe(0);
    expect(calls[0]?.context.cacheWriteTokens).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// normalizeStepUsage — Anthropic normalization and precedence
// ---------------------------------------------------------------------------

describe("normalizeStepUsage", () => {
  it("anthropic cache creation and reads normalize correctly", () => {
    const normalized = normalizeStepUsage({
      usage: { inputTokens: 1000, outputTokens: 25 },
      providerMetadata: {
        anthropic: {
          cacheReadInputTokens: 700,
          cacheCreationInputTokens: 300,
        },
      },
    });
    expect(normalized).toEqual({
      inputTokens: 1000,
      outputTokens: 25,
      cacheReadTokens: 700,
      cacheWriteTokens: 300,
    });
  });

  it("anthropic providerMetadata wins over inputTokenDetails", () => {
    const normalized = normalizeStepUsage({
      usage: {
        inputTokens: 100,
        outputTokens: 1,
        inputTokenDetails: { cacheReadTokens: 999, cacheWriteTokens: 999 },
      },
      providerMetadata: { anthropic: { cacheReadInputTokens: 10 } },
    });
    expect(normalized.cacheReadTokens).toBe(10);
    // anthropic metadata only supplied the read; the write falls back.
    expect(normalized.cacheWriteTokens).toBe(999);
  });

  it("falls back to inputTokenDetails when anthropic metadata is absent", () => {
    const normalized = normalizeStepUsage({
      usage: {
        inputTokens: 100,
        outputTokens: 1,
        inputTokenDetails: { cacheReadTokens: 80, cacheWriteTokens: 20 },
      },
      providerMetadata: { openai: {} },
    });
    expect(normalized.cacheReadTokens).toBe(80);
    expect(normalized.cacheWriteTokens).toBe(20);
  });

  it("zeros when the provider supplies nothing", () => {
    const normalized = normalizeStepUsage({
      usage: { inputTokens: 10, outputTokens: 2 },
    });
    expect(normalized.cacheReadTokens).toBe(0);
    expect(normalized.cacheWriteTokens).toBe(0);
  });
});
