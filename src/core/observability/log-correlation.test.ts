// O5 — correlation between OTel spans, structured logs, and trace.jsonl
// records. The active span's ids land in JSON logs (trace_id/span_id) and
// on every StepTraceWriter record (correlation), flowing to W&B verbatim
// through the existing trace-record event. Legacy records without
// correlation stay readable.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { StepTraceWriter } from "../agents/offSecAgent/trace";
import { AgentEventBus } from "../eventBus";
import { createLogger, setLogSink } from "../logger/structured";
import { getApexTracer } from "../observability";
import {
  type OtelTestHarness,
  requireSpan,
  startOtelTestHarness,
} from "./testkit";

let otel: OtelTestHarness;
let tmpDir: string;
const savedEnv: Record<string, string | undefined> = {};
const ENV_KEYS = ["PENSAR_LOG_FORMAT", "PENSAR_LOG_LEVEL"];

beforeEach(() => {
  otel = startOtelTestHarness();
  tmpDir = mkdtempSync(join(tmpdir(), "correlation-test-"));
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
  }
  process.env.PENSAR_LOG_FORMAT = "json";
  process.env.PENSAR_LOG_LEVEL = "INFO";
});

afterEach(async () => {
  await otel.shutdown();
  rmSync(tmpDir, { recursive: true, force: true });
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  setLogSink(null);
});

function captureLogLines(): string[] {
  const lines: string[] = [];
  setLogSink((line) => lines.push(line));
  return lines;
}

// ---------------------------------------------------------------------------
// Structured logger
// ---------------------------------------------------------------------------

describe("logger correlation", () => {
  it("active spans add valid trace and span IDs to JSON logs", async () => {
    const lines = captureLogLines();
    const logger = createLogger("correlated");

    await getApexTracer().startActiveSpan("log-span", {}, async (span) => {
      logger.info("inside span", { extra: 1 });
      span.end();
    });

    expect(lines).toHaveLength(1);
    const record = JSON.parse(lines[0] ?? "") as Record<string, string>;
    // 32-hex trace id, 16-hex span id — valid OTel formats.
    expect(record.trace_id).toMatch(/^[0-9a-f]{32}$/);
    expect(record.span_id).toMatch(/^[0-9a-f]{16}$/);
    expect(record.msg).toBe("inside span");
    expect(record.extra).toBe(1);
  });

  it("logs outside spans remain unchanged", () => {
    const lines = captureLogLines();
    createLogger("plain").info("outside span");

    expect(lines).toHaveLength(1);
    const record = JSON.parse(lines[0] ?? "") as Record<string, unknown>;
    expect(record.trace_id).toBeUndefined();
    expect(record.span_id).toBeUndefined();
  });

  it("child logs carry the child span id and the shared trace id", async () => {
    const lines = captureLogLines();
    const logger = createLogger("nested");

    await getApexTracer().startActiveSpan("root", {}, async (root) => {
      await getApexTracer().startActiveSpan("child", {}, async (child) => {
        logger.info("in child");
        child.end();
      });
      root.end();
    });

    const record = JSON.parse(lines[0] ?? "") as Record<string, string>;
    const childSpan = requireSpan(otel.getFinishedSpans(), "child");
    const rootSpan = requireSpan(otel.getFinishedSpans(), "root");
    expect(record.span_id).toBe(childSpan.spanContext().spanId);
    expect(record.trace_id).toBe(rootSpan.spanContext().traceId);
  });

  it("JSON logs remain valid one-line records", async () => {
    const lines = captureLogLines();
    const logger = createLogger("oneline");

    await getApexTracer().startActiveSpan("s", {}, async (span) => {
      logger.info("multi", { nested: { deep: "value" } });
      span.end();
    });

    expect(lines).toHaveLength(1);
    expect(lines[0]?.includes("\n")).toBe(false);
    expect(() => JSON.parse(lines[0] ?? "")).not.toThrow();
  });

  it("pretty terminal logs remain readable (no trace ids)", () => {
    process.env.PENSAR_LOG_FORMAT = "pretty";
    const lines = captureLogLines();
    const logger = createLogger("pretty");

    return getApexTracer()
      .startActiveSpan("pretty-span", {}, async (span) => {
        logger.info("pretty message");
        span.end();
      })
      .then(() => {
        expect(lines).toHaveLength(1);
        expect(lines[0]).toContain("pretty message");
        expect(lines[0]).not.toContain("trace_id");
        expect(lines[0]).not.toMatch(/[0-9a-f]{32}/);
      });
  });
});

// ---------------------------------------------------------------------------
// StepTraceWriter / trace.jsonl records
// ---------------------------------------------------------------------------

function makeWriter(eventBus?: AgentEventBus): {
  writer: StepTraceWriter;
  tracePath: string;
} {
  const tracePath = join(tmpDir, "trace.jsonl");
  return {
    writer: new StepTraceWriter({
      tracePath,
      agentId: "ses_agent_1",
      ...(eventBus ? { eventBus } : {}),
    }),
    tracePath,
  };
}

describe("trace record correlation", () => {
  it("root and child records share the same trace ID; child carries its own span ID", async () => {
    const { writer, tracePath } = makeWriter();

    await getApexTracer().startActiveSpan("root", {}, async (root) => {
      writer.recordStep(
        [{ role: "assistant", content: [{ type: "text", text: "root step" }] }],
        { inputTokens: 10, outputTokens: 2 },
      );
      await getApexTracer().startActiveSpan("child", {}, async (child) => {
        writer.recordStep(
          [
            {
              role: "assistant",
              content: [{ type: "text", text: "child step" }],
            },
          ],
          { inputTokens: 5, outputTokens: 1 },
        );
        child.end();
      });
      root.end();
    });

    const lines = readFileSync(tracePath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(2);
    const [rootRecord, childRecord] = lines.map(
      (l) =>
        JSON.parse(l) as {
          correlation?: { traceId?: string; spanId?: string };
        },
    );

    const rootSpan = requireSpan(otel.getFinishedSpans(), "root");
    const childSpan = requireSpan(otel.getFinishedSpans(), "child");
    // Same trace…
    expect(rootRecord.correlation?.traceId).toBe(
      rootSpan.spanContext().traceId,
    );
    expect(childRecord.correlation?.traceId).toBe(
      rootSpan.spanContext().traceId,
    );
    // …but each record names the span it was written under.
    expect(rootRecord.correlation?.spanId).toBe(rootSpan.spanContext().spanId);
    expect(childRecord.correlation?.spanId).toBe(
      childSpan.spanContext().spanId,
    );
  });

  it("records written outside spans carry no correlation", () => {
    const { writer, tracePath } = makeWriter();
    writer.recordStep(
      [{ role: "assistant", content: [{ type: "text", text: "bare" }] }],
      { inputTokens: 1, outputTokens: 1 },
    );

    const record = JSON.parse(
      readFileSync(tracePath, "utf-8").trim(),
    ) as Record<string, unknown>;
    expect(record.correlation).toBeUndefined();
  });

  it("JSONL readers accept old and new records", () => {
    const { writer, tracePath } = makeWriter();
    // A legacy record line, exactly as older Apex wrote it (no correlation).
    const legacy = JSON.stringify({
      type: "step",
      timestamp: new Date().toISOString(),
      agentId: null,
      stepIndex: 0,
      text: "legacy",
    });
    writeFileSync(tracePath, `${legacy}\n`);

    return getApexTracer()
      .startActiveSpan("modern", {}, async (span) => {
        writer.recordStep(
          [{ role: "assistant", content: [{ type: "text", text: "modern" }] }],
          { inputTokens: 1, outputTokens: 1 },
        );
        span.end();
      })
      .then(() => {
        const records = readFileSync(tracePath, "utf-8")
          .trim()
          .split("\n")
          .map((l) => JSON.parse(l) as Record<string, unknown>);
        expect(records).toHaveLength(2);
        expect(records[0]?.correlation).toBeUndefined(); // legacy untouched
        expect(records[1]?.correlation).toBeDefined(); // new correlated
      });
  });

  it("W&B receives correlation through its existing trace-record input", async () => {
    const bus = new AgentEventBus();
    const received: Array<{
      record: { correlation?: { traceId?: string; spanId?: string } };
      subagentId?: string;
    }> = [];
    bus.on("trace-record", (e) => {
      received.push(
        e as {
          record: { correlation?: { traceId?: string; spanId?: string } };
          subagentId?: string;
        },
      );
    });

    const { writer } = makeWriter(bus);
    await getApexTracer().startActiveSpan("wandb-span", {}, async (span) => {
      writer.recordStep(
        [{ role: "assistant", content: [{ type: "text", text: "uploaded" }] }],
        { inputTokens: 3, outputTokens: 1 },
      );
      span.end();
    });

    // The event payload IS what attachWandbToEventBus hands the uploader —
    // no additional upload logic needed for correlation to reach W&B.
    expect(received).toHaveLength(1);
    expect(received[0]?.record.correlation?.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(received[0]?.subagentId).toBe("ses_agent_1");
  });
});
