// O4 — centralized AI telemetry. One builder feeds every model call; the
// operation identifiers are a fixed low-cardinality set; payload capture
// stays opt-in; metadata propagates to span attributes.

import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

const mockState: { model: MockLanguageModelV3 | null } = { model: null };
vi.mock("../ai/utils", async () => {
  const actual =
    await vi.importActual<typeof import("../ai/utils")>("../ai/utils");
  return {
    ...actual,
    getProviderModel: () => {
      if (!mockState.model) throw new Error("mock model not set");
      return mockState.model;
    },
  };
});

const { streamResponse, generateObjectResponse } = await import("../ai");
const { createSummarizationStream } = await import("../ai/utils");
const { createAiTelemetrySettings } = await import("../observability");

import type { OtelTestHarness } from "./testkit";

const { requireSpan, startOtelTestHarness } = await import("./testkit");

const MODEL = "claude-haiku-4-5";

function oneStepTextModel(): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    provider: "mock-anthropic",
    modelId: MODEL,
    doGenerate: async () => ({
      content: [{ type: "text", text: "summary" }],
      finishReason: { unified: "stop", raw: "stop" },
      warnings: [],
      usage: {
        inputTokens: {
          total: 500,
          noCache: 500,
          cacheRead: 0,
          cacheWrite: 0,
        },
        outputTokens: { total: 20, text: 20, reasoning: undefined },
      },
    }),
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: "stream-start", warnings: [] },
          { type: "text-start", id: "t" },
          { type: "text-delta", id: "t", delta: "hello" },
          { type: "text-end", id: "t" },
          {
            type: "finish",
            finishReason: { unified: "stop", raw: "stop" },
            usage: {
              inputTokens: {
                total: 1000,
                noCache: 100,
                cacheRead: 900,
                cacheWrite: 0,
              },
              outputTokens: { total: 20, text: 20, reasoning: undefined },
            },
          },
        ] as unknown as Array<LanguageModelV3StreamPart>,
      }),
    }),
  });
}

/** A model whose step-1 tool args fail zod validation, triggering repair. */
function invalidToolArgsModel(): MockLanguageModelV3 {
  let call = 0;
  return new MockLanguageModelV3({
    provider: "mock-anthropic",
    modelId: MODEL,
    doStream: async () => {
      call += 1;
      if (call === 1) {
        return {
          stream: simulateReadableStream({
            chunks: [
              { type: "stream-start", warnings: [] },
              {
                type: "tool-call",
                toolCallId: "call-bad",
                toolName: "probe",
                // invalid: q must be a string
                input: '{"q":42}',
              },
              {
                type: "finish",
                finishReason: { unified: "tool-calls", raw: "tool_use" },
                usage: {
                  inputTokens: {
                    total: 50,
                    noCache: 50,
                    cacheRead: 0,
                    cacheWrite: 0,
                  },
                  outputTokens: { total: 5, text: 5, reasoning: undefined },
                },
              },
            ] as unknown as Array<LanguageModelV3StreamPart>,
          }),
        };
      }
      return {
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            { type: "text-start", id: "t" },
            { type: "text-delta", id: "t", delta: "repaired" },
            { type: "text-end", id: "t" },
            {
              type: "finish",
              finishReason: { unified: "stop", raw: "stop" },
              usage: {
                inputTokens: {
                  total: 60,
                  noCache: 60,
                  cacheRead: 0,
                  cacheWrite: 0,
                },
                outputTokens: { total: 6, text: 6, reasoning: undefined },
              },
            },
          ] as unknown as Array<LanguageModelV3StreamPart>,
        }),
      };
    },
  });
}

function generateModel(): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    provider: "mock-anthropic",
    modelId: MODEL,
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
        outputTokens: { total: 40, text: 40, reasoning: undefined },
      },
    }),
  });
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    // drain
  }
}

let otel: OtelTestHarness;

beforeEach(() => {
  otel = startOtelTestHarness();
});

afterEach(async () => {
  await otel.shutdown();
  mockState.model = null;
  process.env.AI_TRACE_RECORD_PAYLOADS = undefined;
});

// ---------------------------------------------------------------------------
// Builder units
// ---------------------------------------------------------------------------

describe("createAiTelemetrySettings", () => {
  it("enables telemetry with payload capture off by default", () => {
    const settings = createAiTelemetrySettings({
      operation: "apex.agent.stream",
    });
    expect(settings.isEnabled).toBe(true);
    expect(settings.recordInputs).toBe(false);
    expect(settings.recordOutputs).toBe(false);
    expect(settings.functionId).toBe("apex.agent.stream");
    expect(settings.metadata).toBeUndefined();
  });

  it("follows AI_TRACE_RECORD_PAYLOADS for full capture", () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = "true";
    const settings = createAiTelemetrySettings({
      operation: "apex.structured.generate",
    });
    expect(settings.recordInputs).toBe(true);
    expect(settings.recordOutputs).toBe(true);
  });

  it("propagates session metadata when present", () => {
    const settings = createAiTelemetrySettings({
      operation: "apex.agent.stream",
      sessionId: "ses_1",
    });
    expect(settings.metadata).toEqual({ sessionId: "ses_1" });
  });

  it("operation identifiers are a fixed low-cardinality set", () => {
    const ids = [
      "apex.agent.stream",
      "apex.structured.generate",
      "apex.context.summarize",
      "apex.tool.repair",
    ] as const;
    for (const operation of ids) {
      expect(createAiTelemetrySettings({ operation }).functionId).toBe(
        operation,
      );
    }
    // The builder cannot mint a high-cardinality id (model ids, session ids…)
    // — the operation is a closed union at compile time.
  });
});

// ---------------------------------------------------------------------------
// Every model-call helper: telemetry enabled, stable functionId, payloads
// ---------------------------------------------------------------------------

describe("model-call helpers", () => {
  it("streamResponse enables telemetry with the stable operation id (no model in the name)", async () => {
    mockState.model = oneStepTextModel();
    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        sessionId: "ses_stream",
      }),
    );

    const span = requireSpan(otel.getFinishedSpans(), "ai.streamText");
    // Model id lives in an attribute, not the operation name.
    expect(span.attributes["ai.telemetry.functionId"]).toBe(
      "apex.agent.stream",
    );
    expect(span.attributes["resource.name"]).toBe("apex.agent.stream");
    expect(span.attributes["ai.model.id"]).toBe(MODEL);
    // Session metadata propagates.
    expect(span.attributes["ai.telemetry.metadata.sessionId"]).toBe(
      "ses_stream",
    );
  });

  it("generateObjectResponse creates a model span with structured-generation id", async () => {
    mockState.model = generateModel();
    const output = await generateObjectResponse({
      model: MODEL,
      schema: z.object({ result: z.string() }),
      prompt: "hi",
      sessionId: "ses_obj",
    });

    expect(output).toEqual({ result: "ok" });
    const span = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    expect(span.attributes["ai.telemetry.functionId"]).toBe(
      "apex.structured.generate",
    );
    expect(span.attributes["ai.telemetry.metadata.sessionId"]).toBe("ses_obj");
    // Usage not double-counted: inclusive input, cache reported separately.
    expect(span.attributes["gen_ai.usage.input_tokens"]).toBe(500);
    expect(span.attributes["ai.usage.cachedInputTokens"]).toBe(400);
    expect(span.attributes["ai.usage.inputTokens"]).toBe(500);
  });

  it("generateObjectResponse default mode carries no prompt payload; full mode does", async () => {
    mockState.model = generateModel();
    await generateObjectResponse({
      model: MODEL,
      schema: z.object({ result: z.string() }),
      prompt: "secret objective",
    });
    const opSpan = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    expect(opSpan.attributes["ai.prompt.messages"]).toBeUndefined();
    expect(opSpan.attributes["ai.response.text"]).toBeUndefined();

    // Reset so the full-mode assertions read the second call's spans.
    otel.exporter.reset();
    mockState.model = generateModel();
    process.env.AI_TRACE_RECORD_PAYLOADS = "true";
    await generateObjectResponse({
      model: MODEL,
      schema: z.object({ result: z.string() }),
      prompt: "secret objective",
    });
    // On the generateText path payloads live on the provider-call span
    // (opposite of streamText, where they sit on the operation span).
    const fullSpan = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    expect(String(fullSpan.attributes["ai.prompt.messages"])).toContain(
      "secret objective",
    );
    expect(String(fullSpan.attributes["ai.response.text"])).toContain("result");
  });

  it("direct summarization creates a model span with the summarize id", async () => {
    mockState.model = oneStepTextModel();
    const stream = createSummarizationStream(
      [{ role: "user", content: "history to summarize" }],
      {
        prompt: "resume",
        model: MODEL,
        silent: true,
        sessionId: "ses_sum",
      },
      mockState.model,
    );
    await drain(stream);

    const span = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    expect(span.attributes["ai.telemetry.functionId"]).toBe(
      "apex.context.summarize",
    );
    expect(span.attributes["ai.telemetry.metadata.sessionId"]).toBe("ses_sum");
  });

  it("tool repair runs its model call with the repair id", async () => {
    mockState.model = invalidToolArgsModel();
    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        tools: {
          probe: {
            description: "test tool",
            inputSchema: z.object({ q: z.string() }),
            execute: async (input: { q: string }) => `echo:${input.q}`,
          },
        },
        stopWhen: stepCountIs(2),
      }),
    );

    const generateSpans = otel
      .getFinishedSpans()
      .filter((s) => s.name === "ai.generateText.doGenerate");
    expect(generateSpans.length).toBeGreaterThan(0);
    expect(generateSpans[0]?.attributes["ai.telemetry.functionId"]).toBe(
      "apex.tool.repair",
    );
  });
});

// ---------------------------------------------------------------------------
// Full mode across the stream path: prompts, responses, reasoning, tools
// ---------------------------------------------------------------------------

describe("full payload capture (stream path)", () => {
  it("includes prompt, response, reasoning, and tool payloads", async () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = "true";
    let call = 0;
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doStream: async () => {
        call += 1;
        if (call === 1) {
          return {
            stream: simulateReadableStream({
              chunks: [
                { type: "stream-start", warnings: [] },
                { type: "reasoning-start", id: "r1" },
                { type: "reasoning-delta", id: "r1", delta: "pondering" },
                { type: "reasoning-end", id: "r1" },
                { type: "tool-input-start", id: "c1", toolName: "probe" },
                { type: "tool-input-delta", id: "c1", delta: '{"q":"hi"}' },
                { type: "tool-input-end", id: "c1" },
                {
                  type: "tool-call",
                  toolCallId: "c1",
                  toolName: "probe",
                  input: '{"q":"hi"}',
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
                    outputTokens: { total: 10, text: 10, reasoning: undefined },
                  },
                },
              ] as unknown as Array<LanguageModelV3StreamPart>,
            }),
          };
        }
        return {
          stream: simulateReadableStream({
            chunks: [
              { type: "stream-start", warnings: [] },
              { type: "text-start", id: "t" },
              { type: "text-delta", id: "t", delta: "final answer" },
              { type: "text-end", id: "t" },
              {
                type: "finish",
                finishReason: { unified: "stop", raw: "stop" },
                usage: {
                  inputTokens: {
                    total: 90,
                    noCache: 90,
                    cacheRead: 0,
                    cacheWrite: 0,
                  },
                  outputTokens: { total: 9, text: 9, reasoning: undefined },
                },
              },
            ] as unknown as Array<LanguageModelV3StreamPart>,
          }),
        };
      },
    });

    await drain(
      streamResponse({
        prompt: "secret objective",
        system: "system directive",
        model: MODEL,
        silent: true,
        tools: {
          probe: {
            description: "test tool",
            inputSchema: z.object({ q: z.string() }),
            execute: async (input: { q: string }) => `echo:${input.q}`,
          },
        },
        stopWhen: stepCountIs(2),
      }),
    );

    const spans = otel.getFinishedSpans();
    const streamText = requireSpan(spans, "ai.streamText");
    // System + prompt inside the serialized prompt payload.
    const prompt = String(streamText.attributes["ai.prompt"] ?? "");
    expect(prompt).toContain("secret objective");
    expect(prompt).toContain("system directive");
    // Tool definitions recorded on the provider-call span.
    const doStream = requireSpan(spans, "ai.streamText.doStream");
    expect(String(doStream.attributes["ai.prompt.tools"] ?? "")).toContain(
      "probe",
    );

    const toolSpan = requireSpan(spans, "ai.toolCall");
    expect(String(toolSpan.attributes["ai.toolCall.args"])).toContain(
      '"q":"hi"',
    );
    expect(String(toolSpan.attributes["ai.toolCall.result"])).toContain(
      "echo:hi",
    );

    const responseText = spans
      .map((s) => s.attributes["ai.response.text"])
      .filter(Boolean)
      .map(String)
      .join(" ");
    expect(responseText).toContain("final answer");
    const reasoning = spans
      .map((s) => s.attributes["ai.response.reasoning"])
      .filter(Boolean)
      .map(String)
      .join(" ");
    expect(reasoning).toContain("pondering");
  });
});

// ---------------------------------------------------------------------------
// PR1: auxiliary model lifecycle — summarization and tool-repair callbacks
// are awaited, their synthetic events are handler-safe, and cache usage
// flows through.
// ---------------------------------------------------------------------------

/** A model that streams one text step AND generates with cache + metadata. */
function generateAndStreamModel(): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    provider: "mock-anthropic",
    modelId: MODEL,
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: "stream-start", warnings: [] },
          { type: "text-start", id: "t" },
          { type: "text-delta", id: "t", delta: "resumed" },
          { type: "text-end", id: "t" },
          {
            type: "finish",
            finishReason: { unified: "stop", raw: "stop" },
            usage: {
              inputTokens: {
                total: 100,
                noCache: 100,
                cacheRead: 0,
                cacheWrite: 0,
              },
              outputTokens: { total: 5, text: 5, reasoning: undefined },
            },
          },
        ] as unknown as Array<LanguageModelV3StreamPart>,
      }),
    }),
    doGenerate: async () => ({
      content: [{ type: "text", text: "summary text" }],
      finishReason: { unified: "stop", raw: "stop" },
      warnings: [],
      usage: {
        inputTokens: {
          total: 500,
          noCache: 100,
          cacheRead: 400,
          cacheWrite: 7,
        },
        outputTokens: { total: 40, text: 40, reasoning: undefined },
      },
      providerMetadata: { anthropic: { cacheReadInputTokens: 400 } },
    }),
  });
}

describe("auxiliary model lifecycle", () => {
  it("summarization awaits the wrapped onStepFinish and its synthetic event is handler-safe", async () => {
    mockState.model = generateAndStreamModel();
    const history = [
      { role: "user" as const, content: "history to summarize" },
    ];

    const events: Array<{
      response: { id?: string; messages?: unknown[] };
      providerMetadata?: Record<string, unknown>;
      usage: {
        inputTokens: number;
        inputTokenDetails?: {
          cacheReadTokens?: number;
          cacheWriteTokens?: number;
        };
      };
    }> = [];
    let syntheticCompleted = false;

    const stream = createSummarizationStream(
      history,
      {
        prompt: "resume",
        model: MODEL,
        silent: true,
        onStepFinish: async (event) => {
          const isSynthetic =
            (event as { response: { id?: string } }).response.id ===
            "summarization";
          events.push(event as never);
          // Deferred work (persistence) — the summarization must await it.
          await new Promise((resolve) => setTimeout(resolve, 10));
          if (isSynthetic) syntheticCompleted = true;
        },
      },
      mockState.model,
    );

    await drain(stream);

    // The synthetic event's callback finished — it was awaited, not detached.
    expect(syntheticCompleted).toBe(true);

    const synthetic = events.find((e) => e.response.id === "summarization");
    expect(synthetic).toBeDefined();
    // Handler-safe: handlers spread response.messages; cache and provider
    // metadata survive the synthetic event.
    expect(Array.isArray(synthetic?.response.messages)).toBe(true);
    expect(synthetic?.response.messages).toEqual(history);
    expect(synthetic?.usage.inputTokenDetails?.cacheReadTokens).toBe(400);
    expect(synthetic?.usage.inputTokenDetails?.cacheWriteTokens).toBe(7);
    expect(synthetic?.providerMetadata).toEqual({
      anthropic: { cacheReadInputTokens: 400 },
    });
  });

  it("a rejecting summarization callback surfaces through the resumed stream, not as an unhandled rejection", async () => {
    mockState.model = generateAndStreamModel();

    const stream = createSummarizationStream(
      [{ role: "user", content: "history" }],
      {
        prompt: "resume",
        model: MODEL,
        silent: true,
        onStepFinish: async (event) => {
          if (
            (event as { response: { id?: string } }).response.id ===
            "summarization"
          ) {
            throw new Error("persistence boom");
          }
        },
      },
      mockState.model,
    );

    // Awaited: the failure propagates through the resumed stream. Detached,
    // this would be an unhandled rejection with the stream continuing.
    await expect(drain(stream)).rejects.toThrow("persistence boom");
  });

  it("preserves a successful tool repair when its usage callback rejects", async () => {
    let call = 0;
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doStream: async () => {
        call += 1;
        if (call === 1) {
          return {
            stream: simulateReadableStream({
              chunks: [
                { type: "stream-start", warnings: [] },
                {
                  type: "tool-call",
                  toolCallId: "call-bad",
                  toolName: "probe",
                  input: '{"q":42}',
                },
                {
                  type: "finish",
                  finishReason: { unified: "tool-calls", raw: "tool_use" },
                  usage: {
                    inputTokens: {
                      total: 50,
                      noCache: 50,
                      cacheRead: 0,
                      cacheWrite: 0,
                    },
                    outputTokens: { total: 5, text: 5, reasoning: undefined },
                  },
                },
              ] as unknown as Array<LanguageModelV3StreamPart>,
            }),
          };
        }
        return {
          stream: simulateReadableStream({
            chunks: [
              { type: "stream-start", warnings: [] },
              { type: "text-start", id: "t" },
              { type: "text-delta", id: "t", delta: "done" },
              { type: "text-end", id: "t" },
              {
                type: "finish",
                finishReason: { unified: "stop", raw: "stop" },
                usage: {
                  inputTokens: {
                    total: 60,
                    noCache: 60,
                    cacheRead: 0,
                    cacheWrite: 0,
                  },
                  outputTokens: { total: 6, text: 6, reasoning: undefined },
                },
              },
            ] as unknown as Array<LanguageModelV3StreamPart>,
          }),
        };
      },
      doGenerate: async () => ({
        content: [{ type: "text", text: '{"q":"fixed"}' }],
        finishReason: { unified: "stop", raw: "stop" },
        warnings: [],
        usage: {
          inputTokens: { total: 80, noCache: 30, cacheRead: 50, cacheWrite: 0 },
          outputTokens: { total: 8, text: 8, reasoning: undefined },
        },
        providerMetadata: { anthropic: { cacheReadInputTokens: 50 } },
      }),
    });

    const events: Array<{
      response: { id?: string };
      providerMetadata?: Record<string, unknown>;
      usage: {
        inputTokens: number;
        inputTokenDetails?: { cacheReadTokens?: number };
      };
    }> = [];
    let callbackCompleted = false;
    const executeProbe = vi.fn();

    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        onStepFinish: async (event) => {
          events.push(event as never);
          await new Promise((resolve) => setTimeout(resolve, 5));
          callbackCompleted = true;
          if (
            (event as { response: { id?: string } }).response.id ===
            "tool-repair"
          ) {
            throw new Error("repair persistence boom");
          }
        },
        tools: {
          probe: {
            description: "test tool",
            inputSchema: z.object({ q: z.string() }),
            execute: async (input: { q: string }) => {
              executeProbe(input);
              return `echo:${input.q}`;
            },
          },
        },
        stopWhen: stepCountIs(2),
      }),
    );

    expect(callbackCompleted).toBe(true);
    expect(executeProbe).toHaveBeenCalledWith({ q: "fixed" });

    const repairEvent = events.find((e) => e.response.id === "tool-repair");
    expect(repairEvent).toBeDefined();
    expect(repairEvent?.usage.inputTokens).toBe(80);
    expect(repairEvent?.usage.inputTokenDetails?.cacheReadTokens).toBe(50);
    expect(repairEvent?.providerMetadata).toEqual({
      anthropic: { cacheReadInputTokens: 50 },
    });
  });
});

// ---------------------------------------------------------------------------
// PR4: stable session metadata + structured operation ids
// ---------------------------------------------------------------------------

describe("identity metadata propagation", () => {
  it("streamResponse emits session metadata without redundant identity fields", async () => {
    mockState.model = oneStepTextModel();
    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        sessionId: "ses_root",
      }),
    );

    const span = requireSpan(otel.getFinishedSpans(), "ai.streamText");
    expect(span.attributes["ai.telemetry.metadata.sessionId"]).toBe("ses_root");
    expect(span.attributes["ai.telemetry.metadata.runId"]).toBeUndefined();
    expect(span.attributes["ai.telemetry.metadata.agentId"]).toBeUndefined();
    expect(span.attributes["ai.telemetry.functionId"]).toBe(
      "apex.agent.stream",
    );
  });

  it("generateObjectResponse honors caller operation ids and identity", async () => {
    mockState.model = generateModel();
    await generateObjectResponse({
      model: MODEL,
      schema: z.object({ result: z.string() }),
      prompt: "hi",
      sessionId: "ses_root",
      operation: "apex.finding.cvss",
    });

    const span = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    expect(span.attributes["ai.telemetry.functionId"]).toBe(
      "apex.finding.cvss",
    );
    expect(span.attributes["ai.telemetry.metadata.sessionId"]).toBe("ses_root");
    expect(span.attributes["ai.telemetry.metadata.runId"]).toBeUndefined();
    expect(span.attributes["ai.telemetry.metadata.agentId"]).toBeUndefined();
  });
});
