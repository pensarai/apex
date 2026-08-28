// O1 — the existing agent trace contract. These tests pin what Apex's OTel
// API (`getApexTracer`, `withSubagentSessionBaggage`) and the AI SDK's
// built-in instrumentation already emit, before Stack D changes any
// production behavior. A real tracer provider + in-memory exporter is
// registered per test; the provider model is a deterministic mock so no API
// keys are needed and spans are reproducible.

import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { SpanStatusCode } from "@opentelemetry/api";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

// getProviderModel is patched so the mock model serves the provider call —
// no provider keys, deterministic protocol parts.
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
const { streamResponse } = await import("../ai");
const { getApexTracer, withSubagentSessionBaggage } = await import(
  "../observability"
);
const { parentOf, requireSpan, spansNamed, startOtelTestHarness } =
  await import("./testkit");

// ---------------------------------------------------------------------------
// Mock fixtures
// ---------------------------------------------------------------------------

const MODEL = "claude-haiku-4-5";

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
          "gen_ai.agent.name": label,
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
  });

  it("an in-stream error part currently leaks the root span (known limitation)", async () => {
    // Contract finding: when the model emits an error PART (instead of
    // throwing), the ai.streamText root span (endWhenDone: false) is never
    // ended — no spans export. Pinned as-is; Stack D's O3 root-run spans
    // own their end() on every path instead.
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

    await expect(
      drain(streamResponse({ prompt: "hi", model: MODEL, silent: true })),
    ).rejects.toThrow("model exploded");

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(otel.getFinishedSpans()).toHaveLength(0);
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
