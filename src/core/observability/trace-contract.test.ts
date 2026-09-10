// O1 — the existing agent trace contract. These tests pin what Apex's OTel
// API (`getApexTracer`, `withSubagentSessionBaggage`) and the AI SDK's
// built-in instrumentation already emit, before Stack D changes any
// production behavior. A real tracer provider + in-memory exporter is
// registered per test; the provider model is a deterministic mock so no API
// keys are needed and spans are reproducible.

import { APICallError, type LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { SpanStatusCode, trace } from "@opentelemetry/api";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

// getProviderModel is patched so the mock model serves the provider call —
// no provider keys, deterministic protocol parts. Production wraps the
// resolved model with the passive diagnostics wrapper at its call sites, so
// the mock returns the bare model.
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

import type { OtelTestHarness } from "./testkit";

// Imported AFTER vi.mock so streamResponse's closure picks up the stub.
const { generateObjectResponse, streamResponse } = await import("../ai");
const {
  createGenerationSpanTracker,
  getApexTracer,
  withModelCallDiagnostics,
  withSubagentSessionBaggage,
} = await import("../observability");
const { parentOf, requireSpan, spansNamed, startOtelTestHarness } =
  await import("./testkit");

// ---------------------------------------------------------------------------
// Mock fixtures
// ---------------------------------------------------------------------------

const MODEL = "claude-haiku-4-5";
const ROOT_SESSION_ID = "ses_root";

const NESTED_USAGE = {
  inputTokens: { total: 1000, noCache: 100, cacheRead: 900, cacheWrite: 0 },
  outputTokens: { total: 20, text: 20, reasoning: undefined },
};

function textStepChunks(): Array<Record<string, unknown>> {
  return [
    { type: "stream-start", warnings: [] },
    { type: "text-start", id: "txt-1" },
    { type: "text-delta", id: "txt-1", delta: "hello" },
    { type: "text-end", id: "txt-1" },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage: NESTED_USAGE,
    },
  ];
}

function oneStepTextModel(): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    provider: "mock-anthropic",
    modelId: MODEL,
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: textStepChunks() as unknown as Array<LanguageModelV3StreamPart>,
      }),
    }),
  });
}

/** A two-step stream: step 1 calls a tool, step 2 finishes with text. */
function toolCallingModel(): MockLanguageModelV3 {
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
              { type: "tool-input-start", id: "call-1", toolName: "probe" },
              { type: "tool-input-delta", id: "call-1", delta: '{"q":"hi"}' },
              { type: "tool-input-end", id: "call-1" },
              {
                type: "tool-call",
                toolCallId: "call-1",
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
            { type: "reasoning-start", id: "rsn-1" },
            { type: "reasoning-delta", id: "rsn-1", delta: "thinking hard" },
            { type: "reasoning-end", id: "rsn-1" },
            ...textStepChunks(),
          ] as unknown as Array<LanguageModelV3StreamPart>,
        }),
      };
    },
  });
}

function probeTool() {
  return {
    description: "test tool",
    inputSchema: z.object({ q: z.string() }),
    execute: async (input: { q: string }) => `echo:${input.q}`,
  };
}

/** A helper-path (generateText) model that returns one JSON object. */
function objectResultModel(): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    provider: "mock-anthropic",
    modelId: MODEL,
    doGenerate: async () => ({
      content: [{ type: "text", text: '{"answer": 42}' }],
      finishReason: { unified: "stop", raw: "stop" },
      usage: {
        inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
        outputTokens: { total: 5, text: 5, reasoning: undefined },
      },
      warnings: [],
    }),
  });
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    // drain
  }
}

/**
 * Run a model call inside the exact span structure the agent's drain path
 * uses for subagents (see offensiveSecurityAgent.ts): baggage-scoped
 * active `invoke_agent` span wrapping the stream consumption.
 */
async function subagentInvoke(
  subagentId: string,
  label: string,
  run: () => Promise<void>,
): Promise<void> {
  await withSubagentSessionBaggage(subagentId, () =>
    getApexTracer().startActiveSpan(
      `invoke_agent ${label}`,
      {
        attributes: {
          "gen_ai.operation.name": "invoke_agent",
          "gen_ai.agent.id": subagentId,
          "gen_ai.agent.name": label,
          "gen_ai.conversation.id": ROOT_SESSION_ID,
          "session.id": ROOT_SESSION_ID,
          "pensar.session.id": subagentId,
          "pensar.root_session.id": ROOT_SESSION_ID,
        },
      },
      async (span) => {
        try {
          await run();
        } catch (err) {
          span.recordException(err as Error);
          throw err;
        } finally {
          span.end();
        }
      },
    ),
  );
}

// ---------------------------------------------------------------------------
// Harness lifecycle
// ---------------------------------------------------------------------------

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
// Model spans
// ---------------------------------------------------------------------------

describe("existing trace contract: model spans", () => {
  it("AI SDK emits model spans when a tracer provider exists", async () => {
    mockState.model = oneStepTextModel();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    const spans = otel.getFinishedSpans();
    const streamText = requireSpan(spans, "ai.streamText");
    const doStream = requireSpan(spans, "ai.streamText.doStream");
    expect(streamText).toBeDefined();
    expect(doStream).toBeDefined();
    // The provider call is a child of the streamText operation span.
    expect(parentOf(spans, doStream)?.spanContext().spanId).toBe(
      streamText.spanContext().spanId,
    );
    expect(doStream.attributes["gen_ai.request.model"]).toBe(MODEL);
    expect(streamText.status.code).not.toBe(SpanStatusCode.ERROR);
    expect(streamText.spanContext().traceId).toBe(
      doStream.spanContext().traceId,
    );
  });

  it("token and cache attributes are captured as emitted by the installed AI SDK", async () => {
    mockState.model = oneStepTextModel();

    await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));

    const spans = otel.getFinishedSpans();
    const doStream = requireSpan(spans, "ai.streamText.doStream");
    const streamText = requireSpan(spans, "ai.streamText");
    // gen_ai.* usage lives on the provider-call span…
    expect(doStream.attributes["gen_ai.usage.input_tokens"]).toBe(1000);
    expect(doStream.attributes["gen_ai.usage.output_tokens"]).toBe(20);
    expect(doStream.attributes["gen_ai.response.finish_reasons"]).toBeDefined();
    // …while the operation span carries the ai.usage.* totals.
    expect(streamText.attributes["ai.usage.inputTokens"]).toBe(1000);
    expect(streamText.attributes["ai.usage.outputTokens"]).toBe(20);
    // Cache-read tokens ride the SDK's ai.usage.* attributes — input stays
    // inclusive (1000), cache reported separately (900).
    expect(streamText.attributes["ai.usage.cachedInputTokens"]).toBe(900);
  });

  it("tool execution produces a child tool span", async () => {
    mockState.model = toolCallingModel();

    await drain(
      streamResponse({
        prompt: "hi",
        model: MODEL,
        silent: true,
        tools: { probe: probeTool() },
        stopWhen: stepCountIs(2),
      }),
    );

    const spans = otel.getFinishedSpans();
    const toolSpan = requireSpan(spans, "ai.toolCall");
    const streamText = requireSpan(spans, "ai.streamText");
    expect(toolSpan.attributes["ai.toolCall.name"]).toBe("probe");
    // The tool span is a descendant of the streamText span (same trace).
    expect(toolSpan.spanContext().traceId).toBe(
      streamText.spanContext().traceId,
    );
    expect(toolSpan.parentSpanContext?.spanId).toBeDefined();
  });

  it("failed model calls record an exception", async () => {
    // A provider failure (e.g. HTTP 500) surfaces as a thrown doStream —
    // the SDK records the exception on both spans and ends them.
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doStream: async () => {
        throw new Error("provider 500");
      },
    });

    await expect(
      drain(streamResponse({ prompt: "hi", model: MODEL, silent: true })),
    ).rejects.toThrow("provider 500");

    const spans = otel.getFinishedSpans();
    for (const name of ["ai.streamText", "ai.streamText.doStream"]) {
      const span = requireSpan(spans, name);
      expect(span.status.code, name).toBe(SpanStatusCode.ERROR);
      expect(
        span.events.some(
          (e) =>
            e.name === "exception" &&
            (e.attributes?.["exception.message"] as string) === "provider 500",
        ),
        name,
      ).toBe(true);
    }
    // The wrapper decorates the provider span with the genuinely known type
    // name; a plain Error carries no numeric status, so none is invented.
    const doStream = requireSpan(spans, "ai.streamText.doStream");
    expect(doStream.attributes["error.type"]).toBe("Error");
    expect(doStream.attributes["http.response.status_code"]).toBeUndefined();
  });

  it("an in-stream error part exports a complete tree with error status", async () => {
    // The wrapper drains the post-error tail (the SDK's terminal lifecycle
    // only runs when the stream completes), awaits the terminal response,
    // and marks the root generation span failed before propagating.
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doStream: async () => ({
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            { type: "error", error: new Error("model exploded") },
          ] as unknown as Array<LanguageModelV3StreamPart>,
        }),
      }),
    });

    // The original provider error is preserved.
    await expect(
      drain(streamResponse({ prompt: "hi", model: MODEL, silent: true })),
    ).rejects.toThrow("model exploded");

    // Both generation spans export — deterministic, no sleeps — with the
    // root marked error (the provider-call span completes normally in the
    // SDK and stays unset).
    const spans = otel.getFinishedSpans();
    const streamText = requireSpan(spans, "ai.streamText");
    const doStream = requireSpan(spans, "ai.streamText.doStream");
    expect(streamText.status.code).toBe(SpanStatusCode.ERROR);
    expect(
      streamText.events.some(
        (e) =>
          e.name === "exception" &&
          (e.attributes?.["exception.message"] as string) === "model exploded",
      ),
    ).toBe(true);
    expect(doStream.spanContext().traceId).toBe(
      streamText.spanContext().traceId,
    );
  });

  it("preserves an in-stream error when its tail drain times out", async () => {
    vi.useFakeTimers();
    const providerError = new Error("model exploded before stalled tail");
    let calls = 0;
    let tailWaitStartedResolve!: () => void;
    const tailWaitStarted = new Promise<void>((resolve) => {
      tailWaitStartedResolve = resolve;
    });

    try {
      mockState.model = new MockLanguageModelV3({
        provider: "mock-anthropic",
        modelId: MODEL,
        doStream: async () => {
          calls += 1;
          if (calls > 1) {
            return {
              stream: simulateReadableStream({
                chunks:
                  textStepChunks() as unknown as Array<LanguageModelV3StreamPart>,
              }),
            };
          }

          let emittedError = false;
          return {
            stream: new ReadableStream<LanguageModelV3StreamPart>({
              pull(controller) {
                if (!emittedError) {
                  emittedError = true;
                  controller.enqueue({ type: "stream-start", warnings: [] });
                  controller.enqueue({ type: "error", error: providerError });
                  return;
                }
                tailWaitStartedResolve();
                return new Promise<void>(() => {});
              },
            }),
          };
        },
      });

      const consumption = drain(
        streamResponse({
          prompt: "hi",
          messages: [{ role: "user", content: "hi" }],
          model: MODEL,
          silent: true,
        }),
      );
      const rejection = expect(consumption).rejects.toBe(providerError);

      await tailWaitStarted;
      await vi.advanceTimersByTimeAsync(300_000);
      await rejection;
      expect(calls).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("records details for non-Error provider failures", () => {
    const tracker = createGenerationSpanTracker();
    tracker.tracer.startActiveSpan("ai.streamText", (span) => {
      tracker.markFailed({
        name: "BedrockServiceError",
        message: "throttled",
      });
      span.end();
    });

    const span = requireSpan(otel.getFinishedSpans(), "ai.streamText");
    expect(span.status).toEqual({
      code: SpanStatusCode.ERROR,
      message: '{"name":"BedrockServiceError","message":"throttled"}',
    });
    expect(
      span.events.some(
        (event) =>
          event.name === "exception" &&
          event.attributes?.["exception.message"] ===
            '{"name":"BedrockServiceError","message":"throttled"}',
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Helper generateText path (structured generate, summarize, tool repair)
// ---------------------------------------------------------------------------

describe("existing trace contract: helper generateText path", () => {
  it("structured helper calls emit a correlated wrapper/provider span pair", async () => {
    mockState.model = objectResultModel();

    const result = await generateObjectResponse({
      model: MODEL,
      schema: z.object({ answer: z.number() }),
      prompt: "hi",
    });

    expect(result).toEqual({ answer: 42 });
    const spans = otel.getFinishedSpans();
    const wrapper = requireSpan(spans, "ai.generateText");
    const provider = requireSpan(spans, "ai.generateText.doGenerate");
    // Same correlation contract as the streaming path: the provider call is
    // a child of the operation span, one trace, model attribution preserved.
    expect(parentOf(spans, provider)?.spanContext().spanId).toBe(
      wrapper.spanContext().spanId,
    );
    expect(provider.spanContext().traceId).toBe(wrapper.spanContext().traceId);
    expect(provider.attributes["gen_ai.request.model"]).toBe(MODEL);
    expect(provider.attributes["ai.telemetry.functionId"]).toBe(
      "apex.structured.generate",
    );
    expect(provider.attributes["gen_ai.usage.input_tokens"]).toBe(10);
    expect(wrapper.status.code).not.toBe(SpanStatusCode.ERROR);
  });

  it("a rejected helper call marks both spans failed without inventing usage or status facts", async () => {
    // The production rejection shape: the provider call throws an APICallError
    // whose numeric status is known only to the thrown error object.
    const rejection = new APICallError({
      message: "Request rejected: invalid request",
      url: "https://api.example.com/v1/responses",
      requestBodyValues: {},
      statusCode: 400,
      isRetryable: false,
    });
    let calls = 0;
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doGenerate: async () => {
        calls += 1;
        throw rejection;
      },
    });

    const thrown = await generateObjectResponse({
      model: MODEL,
      schema: z.object({ answer: z.number() }),
      prompt: "hi",
    }).catch((error: unknown) => error);

    // Passive diagnostics: the original error identity and the single
    // physical provider call are preserved.
    expect(thrown).toBe(rejection);
    expect(calls).toBe(1);

    const spans = otel.getFinishedSpans();
    for (const name of ["ai.generateText", "ai.generateText.doGenerate"]) {
      const span = requireSpan(spans, name);
      expect(span.status.code, name).toBe(SpanStatusCode.ERROR);
      expect(
        span.events.some(
          (event) =>
            event.name === "exception" &&
            event.attributes?.["exception.type"] === "AI_APICallError",
        ),
        name,
      ).toBe(true);
    }

    const provider = requireSpan(spans, "ai.generateText.doGenerate");
    // A rejected request never generated: usage stays absent, not zero.
    expect(provider.attributes["gen_ai.usage.input_tokens"]).toBeUndefined();
    expect(provider.attributes["ai.usage.inputTokens"]).toBeUndefined();
    // Known failure facts reach the provider span as bounded attributes:
    // the recognized error type and the numeric status the error carries.
    expect(provider.attributes["error.type"]).toBe("AI_APICallError");
    expect(provider.attributes["http.response.status_code"]).toBe(400);
    // Only those bounded facts — no message or body text is copied.
    expect(provider.attributes["error.message"]).toBeUndefined();
    // Decoration lands on the provider span, not the enclosing wrapper; the
    // wrapper still carries the SDK's exception event.
    const wrapper = requireSpan(spans, "ai.generateText");
    expect(wrapper.attributes["error.type"]).toBeUndefined();
    expect(wrapper.attributes["http.response.status_code"]).toBeUndefined();
  });

  it("an out-of-range status code is not recorded", async () => {
    const rejection = new APICallError({
      message: "Request rejected",
      url: "https://api.example.com/v1/responses",
      requestBodyValues: {},
      statusCode: 99,
      isRetryable: false,
    });
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doGenerate: async () => {
        throw rejection;
      },
    });

    await expect(
      generateObjectResponse({
        model: MODEL,
        schema: z.object({ answer: z.number() }),
        prompt: "hi",
      }),
    ).rejects.toBe(rejection);

    const provider = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    // The identifier-like type name is kept; the out-of-range status is not.
    expect(provider.attributes["error.type"]).toBe("AI_APICallError");
    expect(provider.attributes["http.response.status_code"]).toBeUndefined();
  });

  it("a throwing telemetry hook never replaces the original provider error", async () => {
    // Decoration is best-effort: if the telemetry backend explodes while the
    // failure is being recorded, the provider's own error must still surface.
    const hostileSpan = {
      isRecording: () => true,
      setAttribute: () => {
        throw new Error("telemetry backend exploded");
      },
    };
    const originalActiveSpan = trace.getActiveSpan;
    trace.getActiveSpan = () => hostileSpan as never;
    const rejection = new APICallError({
      message: "Request rejected: invalid request",
      url: "https://api.example.com/v1/responses",
      requestBodyValues: {},
      statusCode: 400,
      isRetryable: false,
    });
    let calls = 0;
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doGenerate: async () => {
        calls += 1;
        throw rejection;
      },
    });
    try {
      const thrown = await generateObjectResponse({
        model: MODEL,
        schema: z.object({ answer: z.number() }),
        prompt: "hi",
      }).catch((error: unknown) => error);
      expect(thrown).toBe(rejection);
      expect(calls).toBe(1);
    } finally {
      trace.getActiveSpan = originalActiveSpan;
    }
  });

  it("a non-Error provider failure stays unattributed — unknown remains unknown", async () => {
    let calls = 0;
    mockState.model = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doGenerate: async () => {
        calls += 1;
        throw "opaque provider failure";
      },
    });

    const thrown = await generateObjectResponse({
      model: MODEL,
      schema: z.object({ answer: z.number() }),
      prompt: "hi",
    }).catch((error: unknown) => error);

    expect(thrown).toBe("opaque provider failure");
    expect(calls).toBe(1);
    const provider = requireSpan(
      otel.getFinishedSpans(),
      "ai.generateText.doGenerate",
    );
    // The SDK still records the failure itself; the wrapper adds nothing it
    // cannot genuinely know.
    expect(provider.status.code).toBe(SpanStatusCode.ERROR);
    expect(provider.attributes["error.type"]).toBeUndefined();
    expect(provider.attributes["http.response.status_code"]).toBeUndefined();
  });

  it("the diagnostic wrapper is inert outside an active span", async () => {
    // No startActiveSpan here: there is no active span, so decoration is a
    // no-op and the pass-through behavior is all that remains.
    const rejection = new Error("no active span");
    let calls = 0;
    const inner = new MockLanguageModelV3({
      provider: "mock-anthropic",
      modelId: MODEL,
      doGenerate: async () => {
        calls += 1;
        if (calls === 1) {
          return {
            content: [{ type: "text", text: '{"answer": 42}' }],
            finishReason: { unified: "stop", raw: "stop" },
            usage: {
              inputTokens: {
                total: 10,
                noCache: 10,
                cacheRead: 0,
                cacheWrite: 0,
              },
              outputTokens: { total: 5, text: 5, reasoning: undefined },
            },
            warnings: [],
          };
        }
        throw rejection;
      },
    });
    const wrapped = withModelCallDiagnostics(inner);

    const result = await wrapped.doGenerate({} as never);
    expect(result.content).toEqual([{ type: "text", text: '{"answer": 42}' }]);
    await expect(wrapped.doGenerate({} as never)).rejects.toBe(rejection);
    expect(calls).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Payload policy
// ---------------------------------------------------------------------------

describe("existing trace contract: payload policy", () => {
  it("AI_TRACE_RECORD_PAYLOADS=false excludes prompts and responses", async () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = "false";
    mockState.model = oneStepTextModel();

    await drain(
      streamResponse({ prompt: "secret prompt", model: MODEL, silent: true }),
    );

    const streamText = requireSpan(otel.getFinishedSpans(), "ai.streamText");
    expect(streamText.attributes["ai.prompt"]).toBeUndefined();
    expect(streamText.attributes["ai.response.text"]).toBeUndefined();
  });

  it("AI_TRACE_RECORD_PAYLOADS=false excludes helper prompts and responses", async () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = "false";
    mockState.model = objectResultModel();

    await generateObjectResponse({
      model: MODEL,
      schema: z.object({ answer: z.number() }),
      prompt: "secret prompt",
    });

    const wrapper = requireSpan(otel.getFinishedSpans(), "ai.generateText");
    expect(wrapper.attributes["ai.prompt"]).toBeUndefined();
    expect(wrapper.attributes["ai.response.text"]).toBeUndefined();
  });

  it("AI_TRACE_RECORD_PAYLOADS=true includes prompts, responses, reasoning, tool arguments, and tool results", async () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = "true";
    mockState.model = toolCallingModel();

    await drain(
      streamResponse({
        prompt: "secret prompt",
        system: "system prompt",
        model: MODEL,
        silent: true,
        tools: { probe: probeTool() },
        stopWhen: stepCountIs(2),
      }),
    );

    const spans = otel.getFinishedSpans();
    const streamText = requireSpan(spans, "ai.streamText");
    const toolSpan = requireSpan(spans, "ai.toolCall");

    const prompt = String(streamText.attributes["ai.prompt"] ?? "");
    expect(prompt).toContain("secret prompt");
    const responseText = spans
      .map((s) => s.attributes["ai.response.text"])
      .filter(Boolean)
      .map(String)
      .join(" ");
    expect(responseText).toContain("hello");
    const reasoning = spans
      .map((s) => s.attributes["ai.response.reasoning"])
      .filter(Boolean)
      .map(String)
      .join(" ");
    expect(reasoning).toContain("thinking hard");
    expect(toolSpan.attributes["ai.toolCall.args"]).toBeDefined();
    expect(String(toolSpan.attributes["ai.toolCall.result"])).toContain(
      "echo:hi",
    );
  });
});

// ---------------------------------------------------------------------------
// Subagent spans
// ---------------------------------------------------------------------------

describe("existing trace contract: subagent spans", () => {
  it("existing subagent span parents model spans correctly", async () => {
    mockState.model = oneStepTextModel();

    await subagentInvoke("ses_subagent_1", "recon-sub", async () => {
      await drain(streamResponse({ prompt: "hi", model: MODEL, silent: true }));
    });

    const spans = otel.getFinishedSpans();
    const invoke = requireSpan(spans, "invoke_agent recon-sub");
    const streamText = requireSpan(spans, "ai.streamText");
    expect(invoke).toBeDefined();
    expect(invoke.attributes["gen_ai.operation.name"]).toBe("invoke_agent");
    expect(invoke.attributes["gen_ai.agent.name"]).toBe("recon-sub");
    expect(streamText).toBeDefined();
    // The model span nests under the subagent span — one trace, correct parent.
    expect(parentOf(spans, streamText)?.spanContext().spanId).toBe(
      invoke.spanContext().spanId,
    );
    expect(streamText.spanContext().traceId).toBe(invoke.spanContext().traceId);
  });

  it("concurrent subagents retain the active parent context", async () => {
    mockState.model = oneStepTextModel();

    const runA = subagentInvoke("ses_sub_a", "agent-a", async () => {
      await drain(
        streamResponse({ prompt: "for a", model: MODEL, silent: true }),
      );
    });
    const runB = subagentInvoke("ses_sub_b", "agent-b", async () => {
      await drain(
        streamResponse({ prompt: "for b", model: MODEL, silent: true }),
      );
    });
    await Promise.all([runA, runB]);

    const spans = otel.getFinishedSpans();
    const invokes = spans.filter((s) => s.name.startsWith("invoke_agent "));
    const streamTexts = spansNamed(spans, "ai.streamText");
    expect(invokes).toHaveLength(2);
    expect(streamTexts).toHaveLength(2);

    // Each model span's parent is its own subagent span — no cross-wiring.
    for (const streamText of streamTexts) {
      const parent = parentOf(spans, streamText);
      expect(parent?.name.startsWith("invoke_agent ")).toBe(true);
    }
    const parentIds = new Set(
      streamTexts.map((s) => s.parentSpanContext?.spanId),
    );
    expect(parentIds.size).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// O3: root agent-run tree — one coherent trace per top-level execution
// ---------------------------------------------------------------------------

describe("root agent-run tree", () => {
  it("model and tool spans belong to the root trace; nested subagents too", async () => {
    mockState.model = toolCallingModel();

    // Subagent invocation nested inside the orchestrator's tool execution —
    // exactly where a spawned agent runs in production.
    const probeTool = () => ({
      description: "spawns a subagent",
      inputSchema: z.object({ q: z.string() }),
      execute: async (input: { q: string }) => {
        const subModel = oneStepTextModel();
        const saved = mockState.model;
        mockState.model = subModel;
        try {
          await subagentInvoke("ses_tree_sub", "recon-sub", async () => {
            await drain(
              streamResponse({ prompt: input.q, model: MODEL, silent: true }),
            );
          });
        } finally {
          mockState.model = saved;
        }
        return "subagent done";
      },
    });

    // Root span with the agent's production attribute shape.
    const rootAttributes = {
      "gen_ai.operation.name": "invoke_agent",
      "gen_ai.agent.id": ROOT_SESSION_ID,
      "gen_ai.agent.name": "default",
      "gen_ai.conversation.id": ROOT_SESSION_ID,
      "session.id": ROOT_SESSION_ID,
      "pensar.session.id": ROOT_SESSION_ID,
      "pensar.root_session.id": ROOT_SESSION_ID,
      "pensar.agent.mode": "default",
    };

    await getApexTracer().startActiveSpan(
      "invoke_agent default",
      { attributes: rootAttributes },
      async (rootSpan) => {
        try {
          await drain(
            streamResponse({
              prompt: "hi",
              model: MODEL,
              silent: true,
              tools: { probe: probeTool() },
              stopWhen: stepCountIs(2),
            }),
          );
        } finally {
          rootSpan.end();
        }
      },
    );

    const spans = otel.getFinishedSpans();
    const root = requireSpan(spans, "invoke_agent default");
    const rootStreamText = requireSpan(spans, "ai.streamText");
    const doStream = requireSpan(spans, "ai.streamText.doStream");
    const toolSpan = requireSpan(spans, "ai.toolCall");
    const subInvoke = requireSpan(spans, "invoke_agent recon-sub");
    const subStreamTexts = spans.filter(
      (s) => s.name === "ai.streamText" && s !== rootStreamText,
    );

    // The expected tree, one trace:
    //   invoke_agent root → ai.streamText → doStream → ai.toolCall
    //     → invoke_agent subagent → ai.streamText → doStream
    const rootTraceId = root.spanContext().traceId;
    for (const span of [rootStreamText, doStream, toolSpan, subInvoke]) {
      expect(span.spanContext().traceId, span.name).toBe(rootTraceId);
    }
    expect(subStreamTexts).toHaveLength(1);
    expect(subStreamTexts[0]?.spanContext().traceId).toBe(rootTraceId);
    // The subagent span nests under the tool span.
    expect(parentOf(spans, subInvoke)?.spanContext().spanId).toBe(
      toolSpan.spanContext().spanId,
    );
    // Root and current-agent identity survive without redundant run ids.
    expect(root.attributes["gen_ai.agent.id"]).toBe(ROOT_SESSION_ID);
    expect(root.attributes["gen_ai.conversation.id"]).toBe(ROOT_SESSION_ID);
    expect(root.attributes["pensar.session.id"]).toBe(ROOT_SESSION_ID);
    expect(root.attributes["pensar.root_session.id"]).toBe(ROOT_SESSION_ID);
    expect(root.attributes["pensar.run.id"]).toBeUndefined();
    expect(root.attributes["pensar.agent.mode"]).toBe("default");
    expect(subInvoke.attributes["gen_ai.agent.id"]).toBe("ses_tree_sub");
    expect(subInvoke.attributes["gen_ai.conversation.id"]).toBe(
      ROOT_SESSION_ID,
    );
    expect(subInvoke.attributes["pensar.session.id"]).toBe("ses_tree_sub");
    expect(subInvoke.attributes["pensar.root_session.id"]).toBe(
      ROOT_SESSION_ID,
    );
  });

  it("concurrent subagents under one root keep their own parents and trace", async () => {
    mockState.model = oneStepTextModel();

    await getApexTracer().startActiveSpan(
      "invoke_agent default",
      {
        attributes: {
          "gen_ai.operation.name": "invoke_agent",
          "gen_ai.agent.id": ROOT_SESSION_ID,
          "gen_ai.agent.name": "default",
          "gen_ai.conversation.id": ROOT_SESSION_ID,
          "session.id": ROOT_SESSION_ID,
          "pensar.session.id": ROOT_SESSION_ID,
          "pensar.root_session.id": ROOT_SESSION_ID,
          "pensar.agent.mode": "default",
        },
      },
      async (rootSpan) => {
        try {
          await Promise.all([
            subagentInvoke("ses_c1", "agent-a", async () => {
              await drain(
                streamResponse({ prompt: "a", model: MODEL, silent: true }),
              );
            }),
            subagentInvoke("ses_c2", "agent-b", async () => {
              await drain(
                streamResponse({ prompt: "b", model: MODEL, silent: true }),
              );
            }),
          ]);
        } finally {
          rootSpan.end();
        }
      },
    );

    const spans = otel.getFinishedSpans();
    const root = requireSpan(spans, "invoke_agent default");
    const subInvokes = spans.filter((s) => s.name.startsWith("invoke_agent "));
    const streamTexts = spans.filter((s) => s.name === "ai.streamText");

    expect(subInvokes).toHaveLength(3); // root + two subagents
    expect(streamTexts).toHaveLength(2);
    // Everything shares the root trace…
    for (const span of [...subInvokes, ...streamTexts]) {
      expect(span.spanContext().traceId).toBe(root.spanContext().traceId);
    }
    // …and each model span parents its own subagent span.
    for (const streamText of streamTexts) {
      const parent = parentOf(spans, streamText);
      expect(parent?.name.startsWith("invoke_agent ")).toBe(true);
      expect(parent).not.toBe(root);
    }
  });
});
