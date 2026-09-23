import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { trace } from "@opentelemetry/api";
import { type ModelMessage, simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type OtelTestHarness,
  requireSpan,
  startOtelTestHarness,
} from "../observability/testkit";
import {
  estimateMessageTokens,
  fitMessagesToContext,
} from "./contextManagement";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const { streamResponse } = await import("./ai");
const { createSummarizationStream } = await import("./utils");

const MODEL = "claude-haiku-4-5";
const usage = {
  inputTokens: { total: 100, noCache: 100, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 10, text: 10, reasoning: undefined },
};

function model() {
  return new MockLanguageModelV3({
    modelId: MODEL,
    doGenerate: async () => ({
      content: [{ type: "text", text: "A compact summary" }],
      finishReason: { unified: "stop", raw: "stop" },
      usage,
      warnings: [],
    }),
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: "text-start", id: "t" },
          { type: "text-delta", id: "t", delta: "Done" },
          { type: "text-end", id: "t" },
          {
            type: "finish",
            finishReason: { unified: "stop", raw: "stop" },
            usage,
          },
        ],
      }),
    }),
  });
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    /* consume the SDK lifecycle */
  }
}

function toolHistory(): ModelMessage[] {
  return Array.from({ length: 10 }, (_, i) => [
    {
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolName: "probe",
          toolCallId: `c${i}`,
          input: {},
        },
      ],
    },
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolName: "probe",
          toolCallId: `c${i}`,
          output: { type: "text", value: "evidence ".repeat(2000) },
        },
      ],
    },
  ]).flat() as ModelMessage[];
}

describe("compaction observability", () => {
  let otel: OtelTestHarness;
  let directory: string;
  beforeEach(() => {
    otel = startOtelTestHarness();
    directory = mkdtempSync(join(tmpdir(), "apex-compaction-"));
    state.model = model();
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    await otel.shutdown();
    rmSync(directory, { recursive: true, force: true });
  });
  const context = {
    trigger: "proactive" as const,
    model: MODEL,
    sessionId: "ses_research",
  };

  it("records cascading reductions once, without changing their result", () => {
    const messages = toolHistory();
    const options = {
      contextWindow: 400,
      maxOutputTokens: 0,
      overheadTokens: 0,
      safetyMarginTokens: 0,
      sessionPath: directory,
    };
    const baseline = fitMessagesToContext(messages, options);
    const observed = fitMessagesToContext(messages, {
      ...options,
      telemetry: context,
    });
    expect(observed.messages).toEqual(baseline.messages);
    expect(observed.estimatedInputTokens).toBe(baseline.estimatedInputTokens);
    const spans = otel.getFinishedSpans();
    expect(spans).toHaveLength(1);
    expect(spans[0]?.attributes).toMatchObject({
      "apex.compaction.method": "fit",
      "apex.compaction.trigger": "proactive",
      "apex.compaction.before.estimated_tokens":
        estimateMessageTokens(messages),
      "apex.compaction.after.estimated_tokens": observed.estimatedInputTokens,
      "apex.compaction.affected_results": 10,
      "apex.compaction.message_budget_tokens": 400,
    });
    const layers = JSON.parse(
      String(spans[0]?.attributes["apex.compaction.layers"]),
    );
    expect(layers.map((layer: { method: string }) => layer.method)).toContain(
      "truncate",
    );
    expect(layers.map((layer: { method: string }) => layer.method)).toContain(
      "snip",
    );
    expect(spans[0]?.attributes["ai.usage.inputTokens"]).toBeUndefined();
  });

  it("doesn't emit spans for a context that already fits", () => {
    const messages: ModelMessage[] = [{ role: "user", content: "small" }];
    const result = fitMessagesToContext(messages, {
      contextWindow: 20_000,
      maxOutputTokens: 100,
      telemetry: context,
    });
    expect(result.messages).toBe(messages);
    expect(otel.getFinishedSpans()).toEqual([]);
  });

  it("contains tracer failures without changing context fitting", () => {
    vi.spyOn(trace, "getTracer").mockImplementation(() => {
      throw new Error("exporter unavailable");
    });
    expect(() =>
      fitMessagesToContext(toolHistory(), {
        contextWindow: 400,
        maxOutputTokens: 0,
        overheadTokens: 0,
        safetyMarginTokens: 0,
        sessionPath: directory,
        telemetry: context,
      }),
    ).not.toThrow();
  });

  it("ends summarization before resuming and links the subsequent inference", async () => {
    const summaryModel = model();
    state.model = summaryModel;
    const stream = createSummarizationStream(
      [{ role: "user", content: "history" }],
      {
        prompt: "continue",
        model: MODEL,
        silent: true,
        sessionId: "ses_child",
      },
      summaryModel,
    );
    await drain(stream);
    const spans = otel.getFinishedSpans();
    const compaction = requireSpan(spans, "apex.context.compact");
    const summary = spans.find(
      (span) => span.name === "ai.generateText.doGenerate",
    );
    const resumed = requireSpan(spans, "ai.streamText");
    expect(compaction?.attributes).toMatchObject({
      "apex.compaction.outcome": "completed",
      "pensar.session.id": "ses_child",
    });
    for (const span of [summary, resumed]) {
      expect(span?.attributes["ai.telemetry.metadata.compactionSpanId"]).toBe(
        compaction?.spanContext().spanId,
      );
      expect(span?.attributes["ai.telemetry.metadata.compactionTraceId"]).toBe(
        compaction?.spanContext().traceId,
      );
    }
    expect(
      BigInt(compaction.endTime[0]) * 1_000_000_000n +
        BigInt(compaction.endTime[1]),
    ).toBeLessThanOrEqual(
      BigInt(resumed.startTime[0]) * 1_000_000_000n +
        BigInt(resumed.startTime[1]),
    );
  });

  it("preserves model-visible requests and call counts with telemetry enabled", async () => {
    const options = {
      prompt: "original task",
      model: MODEL,
      silent: true,
      messages: [
        { role: "user" as const, content: "irreducible ".repeat(100_000) },
      ],
    };
    await otel.shutdown();
    const baseline = model();
    state.model = baseline;
    await drain(streamResponse(options));
    otel = startOtelTestHarness();
    const observed = model();
    state.model = observed;
    await drain(streamResponse(options));
    expect(observed.doGenerateCalls.map((call) => call.prompt)).toEqual(
      baseline.doGenerateCalls.map((call) => call.prompt),
    );
    expect(observed.doStreamCalls.map((call) => call.prompt)).toEqual(
      baseline.doStreamCalls.map((call) => call.prompt),
    );
    expect(observed.doStreamCalls.map((call) => call.maxOutputTokens)).toEqual(
      baseline.doStreamCalls.map((call) => call.maxOutputTokens),
    );
  });

  it("keeps concurrent subagent continuation links separate", async () => {
    const childModel = model();
    state.model = childModel;
    await Promise.all(
      ["ses_child_a", "ses_child_b"].map((sessionId) =>
        drain(
          createSummarizationStream(
            [{ role: "user", content: sessionId }],
            { prompt: "continue", model: MODEL, silent: true, sessionId },
            childModel,
          ),
        ),
      ),
    );
    const spans = otel.getFinishedSpans();
    for (const sessionId of ["ses_child_a", "ses_child_b"]) {
      const compact = spans.find(
        (span) =>
          span.name === "apex.context.compact" &&
          span.attributes["pensar.session.id"] === sessionId,
      );
      const resumed = spans.find(
        (span) =>
          span.name === "ai.streamText" &&
          span.attributes["ai.telemetry.metadata.sessionId"] === sessionId,
      );
      expect(compact).toBeDefined();
      expect(
        resumed?.attributes["ai.telemetry.metadata.compactionSpanId"],
      ).toBe(compact?.spanContext().spanId);
      expect(
        compact?.attributes["apex.compaction.previous_span_id"],
      ).toBeUndefined();
    }
  });

  it("records summary cancellation without hiding the original error", async () => {
    const cancelled = new Error("cancelled");
    cancelled.name = "AbortError";
    state.model = new MockLanguageModelV3({
      doGenerate: async () => {
        throw cancelled;
      },
    });
    const stream = createSummarizationStream(
      [{ role: "user", content: "history" }],
      {
        prompt: "continue",
        model: MODEL,
        silent: true,
      },
      state.model,
    );
    await expect(drain(stream)).rejects.toBe(cancelled);
    expect(
      otel
        .getFinishedSpans()
        .find((span) => span.name === "apex.context.compact")?.attributes[
        "apex.compaction.outcome"
      ],
    ).toBe("aborted");
  });

  it("records proactive escalation, summary failure and the minimal reset", async () => {
    const normal = model();
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doGenerate: async () => {
        throw new Error("context length exceeded");
      },
      doStream: (options) => normal.doStream(options),
    });
    await drain(
      streamResponse({
        prompt: "original task",
        model: MODEL,
        silent: true,
        sessionId: "ses_fallback",
        messages: [{ role: "user", content: "irreducible ".repeat(100_000) }],
      }),
    );
    const spans = otel.getFinishedSpans();
    const compact = spans.filter(
      (span) => span.name === "apex.context.compact",
    );
    expect(compact[0]?.attributes["apex.compaction.trigger"]).toBe("proactive");
    expect(
      compact.some(
        (span) => span.attributes["apex.compaction.outcome"] === "failed",
      ),
    ).toBe(true);
    const reset = compact.find(
      (span) => span.attributes["apex.compaction.method"] === "reset",
    );
    expect(reset?.attributes["apex.compaction.trigger"]).toBe(
      "summary_overflow",
    );
    expect(reset?.attributes["apex.compaction.previous_span_id"]).toBeTruthy();
    expect(
      spans.find((span) => span.name === "ai.streamText")?.attributes[
        "ai.telemetry.metadata.compactionSpanId"
      ],
    ).toBe(reset?.spanContext().spanId);
  });
});
