import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { trace } from "@opentelemetry/api";
import { type ModelMessage, simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runWithAiPayloadCapture } from "../observability";
import {
  type OtelTestHarness,
  requireSpan,
  startOtelTestHarness,
} from "../observability/testkit";
import { beginCompaction } from "./compactionTelemetry";
import {
  estimateMessageTokens,
  fitMessagesToContext,
} from "./contextManagement";
import { createNativeRolloutEvidenceCapture } from "./native-rollout-evidence";

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

function toolHistory(length = 10): ModelMessage[] {
  return Array.from({ length }, (_, i) => [
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
    vi.unstubAllEnvs();
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
    const nativeOperations: string[] = [];
    const native = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-compaction-parity",
      sink: {
        write: (envelope) => {
          nativeOperations.push(envelope.operationKind);
        },
      },
    });
    await native.run(() =>
      runWithAiPayloadCapture(true, () => drain(streamResponse(options))),
    );
    await native.flush();
    expect(nativeOperations).toEqual(["context.summarize", "agent.stream"]);
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

  it("honors the run-scoped payload gate without reading context or result evidence", () => {
    vi.stubEnv("AI_TRACE_RECORD_PAYLOADS", "true");
    const evidence = vi.fn(() => {
      throw new Error("must not read payloads");
    });
    runWithAiPayloadCapture(false, () => {
      const telemetry = beginCompaction("fit", context);
      telemetry?.capture("before", evidence);
      telemetry?.capture("after", evidence);
      telemetry?.result("1:0", evidence);
      telemetry?.finish("completed");
    });
    expect(evidence).not.toHaveBeenCalled();
    const span = requireSpan(otel.getFinishedSpans(), "apex.context.compact");
    for (const phase of ["before", "after", "results"]) {
      expect(span.attributes[`apex.compaction.evidence.${phase}.status`]).toBe(
        "disabled",
      );
      expect(
        span.attributes[`apex.compaction.evidence.${phase}.json`],
      ).toBeUndefined();
    }
  });

  it("captures the transformation and distinguishes successful saves from silent write failures", () => {
    mkdirSync(join(directory, "tool-results", "c0.txt"), { recursive: true });
    const messages = toolHistory();
    const fitted = runWithAiPayloadCapture(true, () =>
      fitMessagesToContext(messages, {
        contextWindow: 400,
        maxOutputTokens: 0,
        overheadTokens: 0,
        safetyMarginTokens: 0,
        sessionPath: directory,
        system: "research system",
        telemetry: context,
      }),
    );
    const { attributes } = requireSpan(
      otel.getFinishedSpans(),
      "apex.context.compact",
    );
    expect(
      JSON.parse(String(attributes["apex.compaction.evidence.before.json"])),
    ).toEqual({ messages, system: "research system" });
    expect(
      JSON.parse(String(attributes["apex.compaction.evidence.after.json"])),
    ).toEqual({ messages: fitted.messages, system: "research system" });
    expect(attributes["apex.compaction.persistence.written"]).toBe(9);
    expect(attributes["apex.compaction.persistence.write_failed"]).toBe(1);
    const results = JSON.parse(
      String(attributes["apex.compaction.evidence.results.json"]),
    );
    expect(results).toHaveLength(10);
    expect(results[0]).toMatchObject({
      position: "1:0",
      toolCallId: "c0",
      method: "snip",
      preservation: "write_failed",
      originalChars: 18_000,
      inputChars: 18_000,
    });
    expect(results[1]).toMatchObject({
      toolCallId: "c1",
      preservation: "written",
    });
    expect(
      readFileSync(join(directory, "tool-results", "c1.txt"), "utf8"),
    ).toBe("evidence ".repeat(2000));
    expect(attributes["apex.compaction.evidence.capture_ms"]).toEqual(
      expect.any(Number),
    );
  });

  it("does not treat old archive references or snipped outputs as verified files", () => {
    const options = {
      contextWindow: 6000,
      maxOutputTokens: 0,
      overheadTokens: 0,
      safetyMarginTokens: 0,
      sessionPath: directory,
    };
    const earlier = fitMessagesToContext(toolHistory(), options);
    runWithAiPayloadCapture(true, () =>
      fitMessagesToContext(earlier.messages, {
        ...options,
        contextWindow: 400,
        telemetry: context,
      }),
    );
    const attributes = requireSpan(
      otel.getFinishedSpans(),
      "apex.context.compact",
    ).attributes;
    const results = JSON.parse(
      String(attributes["apex.compaction.evidence.results.json"]),
    );
    expect(
      results.every(
        (result: { preservation: string }) =>
          result.preservation === "referenced_unverified",
      ),
    ).toBe(true);
    expect(attributes["apex.compaction.persistence.written"]).toBe(0);
    otel.exporter.reset();
    runWithAiPayloadCapture(true, () =>
      fitMessagesToContext(toolHistory(), {
        ...options,
        sessionPath: undefined,
        telemetry: context,
      }),
    );
    const snipped = requireSpan(
      otel.getFinishedSpans(),
      "apex.context.compact",
    );
    const unsaved = JSON.parse(
      String(snipped.attributes["apex.compaction.evidence.results.json"]),
    );
    expect(
      unsaved.every(
        (result: { preservation: string }) =>
          result.preservation === "not_persisted",
      ),
    ).toBe(true);
  });

  it("preserves tool evidence omitted by the summarizer and links its actual request and response", async () => {
    const summaryModel = model();
    state.model = summaryModel;
    const messages: ModelMessage[] = [
      ...toolHistory(),
      { role: "user", content: "continue researching" },
    ];
    await runWithAiPayloadCapture(true, () =>
      drain(
        createSummarizationStream(
          messages,
          {
            prompt: "original task",
            system: "research system",
            model: MODEL,
            silent: true,
          },
          summaryModel,
        ),
      ),
    );
    const spans = otel.getFinishedSpans();
    const compact = requireSpan(spans, "apex.context.compact");
    const before = JSON.parse(
      String(compact.attributes["apex.compaction.evidence.before.json"]),
    );
    expect(before).toEqual({
      messages,
      prompt: "original task",
      system: "research system",
    });
    const summary = requireSpan(spans, "ai.generateText.doGenerate");
    expect(summary.attributes["ai.prompt.messages"]).toContain(
      "continue researching",
    );
    expect(summary.attributes["ai.prompt.messages"]).not.toContain(
      "evidence evidence",
    );
    expect(summary.attributes["ai.response.text"]).toBe("A compact summary");
    expect(summary.attributes["ai.telemetry.metadata.compactionSpanId"]).toBe(
      compact.spanContext().spanId,
    );
    const after = JSON.parse(
      String(compact.attributes["apex.compaction.evidence.after.json"]),
    );
    expect(after.messages[0].content).toContain("A compact summary");
    expect(summaryModel.doStreamCalls[0]?.prompt).toMatchObject([
      { role: "system", content: after.system },
      {
        role: "user",
        content: [{ type: "text", text: after.messages[0].content }],
      },
    ]);
  });

  it("marks withheld and failed evidence explicitly while allowing compaction to finish", () => {
    runWithAiPayloadCapture(true, () => {
      const compact = beginCompaction("summarize", context);
      compact?.capture("before", () => ({
        messages: "x".repeat(3 * 1024 * 1024),
      }));
      compact?.capture("after", () => {
        throw new Error("sensitive capture failure");
      });
      compact?.finish("completed");
    });
    const { attributes } = requireSpan(
      otel.getFinishedSpans(),
      "apex.context.compact",
    );
    expect(attributes["apex.compaction.outcome"]).toBe("completed");
    expect(attributes["apex.compaction.evidence.before.status"]).toBe(
      "truncated",
    );
    expect(attributes["apex.compaction.evidence.before.reason"]).toBe(
      "byte_limit",
    );
    expect(attributes["apex.compaction.evidence.before.json"]).toBeUndefined();
    expect(attributes["apex.compaction.evidence.after.status"]).toBe("failed");
    expect(JSON.stringify(attributes)).not.toContain(
      "sensitive capture failure",
    );
  });

  it("marks a partial affected-result list instead of claiming complete evidence", () => {
    runWithAiPayloadCapture(true, () =>
      fitMessagesToContext(toolHistory(300), {
        contextWindow: 30_000,
        maxOutputTokens: 0,
        overheadTokens: 0,
        safetyMarginTokens: 0,
        telemetry: context,
      }),
    );
    const { attributes } = requireSpan(
      otel.getFinishedSpans(),
      "apex.context.compact",
    );
    expect(attributes["apex.compaction.affected_results"]).toBeGreaterThan(256);
    expect(attributes["apex.compaction.evidence.results.status"]).toBe(
      "truncated",
    );
    expect(attributes["apex.compaction.evidence.results.reason"]).toBe(
      "result_limit",
    );
    expect(
      JSON.parse(String(attributes["apex.compaction.evidence.results.json"])),
    ).toHaveLength(256);
  });

  it("keeps concurrent subagent continuation links separate", async () => {
    const childModel = model();
    state.model = childModel;
    await Promise.all(
      ["ses_child_a", "ses_child_b"].map((sessionId) =>
        runWithAiPayloadCapture(sessionId === "ses_child_a", () =>
          drain(
            createSummarizationStream(
              [{ role: "user", content: sessionId }],
              { prompt: "continue", model: MODEL, silent: true, sessionId },
              childModel,
            ),
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
        compact?.attributes["apex.compaction.evidence.before.status"],
      ).toBe(sessionId === "ses_child_a" ? "available" : "disabled");
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
    await runWithAiPayloadCapture(true, () =>
      drain(
        streamResponse({
          prompt: "original task",
          model: MODEL,
          silent: true,
          sessionId: "ses_fallback",
          messages: [{ role: "user", content: "irreducible ".repeat(100_000) }],
        }),
      ),
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
      compact.find(
        (span) => span.attributes["apex.compaction.outcome"] === "failed",
      )?.attributes["apex.compaction.evidence.after.status"],
    ).toBe("unavailable");
    expect(
      JSON.parse(
        String(reset?.attributes["apex.compaction.evidence.after.json"]),
      )?.messages,
    ).toEqual([{ role: "user", content: "original task" }]);
    expect(
      spans.find((span) => span.name === "ai.streamText")?.attributes[
        "ai.telemetry.metadata.compactionSpanId"
      ],
    ).toBe(reset?.spanContext().spanId);
  });
});
