import {
  type Attributes,
  type Span,
  type SpanContext,
  SpanStatusCode,
} from "@opentelemetry/api";
import { getApexTracer, shouldRecordAiPayloads } from "../observability";
import {
  CONTEXT_EVIDENCE_BYTES,
  encodeCompactionEvidence,
  MAX_RESULT_EVIDENCE,
  RESULT_EVIDENCE_BYTES,
} from "./compactionEvidence";

export type CompactionLink = SpanContext;
export type CompactionTrigger =
  | "proactive"
  | "context_overflow"
  | "summary_overflow";
export type CompactionMethod = "fit" | "summarize" | "reset";

export interface CompactionContext {
  trigger: CompactionTrigger;
  model: string;
  sessionId?: string;
  restartDepth?: number;
  previous?: CompactionLink;
}

export interface CompactionLayer {
  method: "truncate" | "snip";
  threshold: number;
  tokensBefore: number;
  tokensAfter: number;
}

interface ResultEvidence {
  method: "truncate" | "snip";
  toolCallId: string;
  toolName: string;
  inputChars: number;
  outputChars: number;
  originalChars: number;
  preservation:
    | "written"
    | "write_failed"
    | "referenced_unverified"
    | "not_persisted";
  path?: string;
}

export class CompactionTelemetry {
  private ended = false;
  private readonly results = new Set<string>();
  private readonly layers: CompactionLayer[] = [];
  private readonly capturePayloads = shouldRecordAiPayloads();
  private readonly resultEvidence = new Map<string, ResultEvidence>();
  private resultEvidenceFailed = false;
  private written = 0;
  private writeFailed = 0;
  private captureMs = 0;
  readonly link: CompactionLink;

  constructor(
    private readonly span: Span,
    private readonly method: CompactionMethod,
  ) {
    this.link = span.spanContext();
    for (const phase of ["before", "after"]) {
      this.attributes({
        [`apex.compaction.evidence.${phase}.status`]: this.capturePayloads
          ? "unavailable"
          : "disabled",
        ...(this.capturePayloads
          ? { [`apex.compaction.evidence.${phase}.reason`]: "not_captured" }
          : {}),
      });
    }
  }

  private record(fn: () => void): void {
    if (this.ended) return;
    try {
      fn();
    } catch {
      // Observability must not change context recovery or its original error.
    }
  }

  attributes(values: Attributes): void {
    this.record(() => this.span.setAttributes(values));
  }

  measure(
    phase: "before" | "after",
    tokens: () => number,
    messageCount: number,
  ): void {
    this.record(() =>
      this.span.setAttributes({
        [`apex.compaction.${phase}.estimated_tokens`]: tokens(),
        [`apex.compaction.${phase}.message_count`]: messageCount,
      }),
    );
  }

  capture(phase: "before" | "after", value: () => unknown): void {
    if (!this.capturePayloads) return;
    this.record(() => this.captureValue(phase, value, CONTEXT_EVIDENCE_BYTES));
  }

  private captureValue(
    name: string,
    value: () => unknown,
    limit: number,
  ): void {
    const start = performance.now();
    const prefix = `apex.compaction.evidence.${name}`;
    this.span.setAttribute(`${prefix}.limit_bytes`, limit);
    try {
      const encoded = encodeCompactionEvidence(value(), limit);
      this.span.setAttributes({
        [`${prefix}.status`]: encoded.status,
        [`${prefix}.reason`]: encoded.reason ?? "",
        [`${prefix}.bytes`]: encoded.bytes,
        ...(encoded.json === undefined
          ? {}
          : { [`${prefix}.json`]: encoded.json }),
      });
    } catch {
      this.span.setAttributes({
        [`${prefix}.status`]: "failed",
        [`${prefix}.reason`]: "capture_failed",
      });
    } finally {
      this.captureMs += performance.now() - start;
    }
  }

  persisted(status: "written" | "write_failed"): void {
    if (status === "written") this.written++;
    else this.writeFailed++;
  }

  result(key: string, evidence: () => ResultEvidence): void {
    this.record(() => {
      this.results.add(key);
      if (!this.capturePayloads) return;
      const previous = this.resultEvidence.get(key);
      if (!previous && this.resultEvidence.size >= MAX_RESULT_EVIDENCE) return;
      try {
        const next = evidence();
        this.resultEvidence.set(key, {
          ...next,
          inputChars: previous?.inputChars ?? next.inputChars,
          ...(previous &&
          previous.path === next.path &&
          next.preservation === "referenced_unverified"
            ? { preservation: previous.preservation }
            : {}),
        });
      } catch {
        this.resultEvidenceFailed = true;
      }
    });
  }

  layer(layer: CompactionLayer): void {
    this.record(() => this.layers.push(layer));
  }

  finish(
    outcome: "completed" | "insufficient_reduction",
    values: Attributes = {},
  ): void {
    this.record(() => {
      this.span.setAttributes({
        ...values,
        "apex.compaction.outcome": outcome,
      });
      this.span.setStatus({ code: SpanStatusCode.OK });
    });
    this.end();
  }

  fail(error: unknown, aborted = false): void {
    this.record(() => {
      const cancelled =
        aborted || (error instanceof Error && error.name === "AbortError");
      this.span.setAttribute(
        "apex.compaction.outcome",
        cancelled ? "aborted" : "failed",
      );
      if (error instanceof Error && /^[A-Za-z0-9._-]{1,64}$/.test(error.name)) {
        this.span.setAttribute("error.type", error.name);
      }
      this.span.setStatus({ code: SpanStatusCode.ERROR });
    });
    this.end();
  }

  private end(): void {
    this.record(() => {
      if (this.method === "fit") {
        this.span.setAttributes({
          "apex.compaction.affected_results": this.results.size,
          "apex.compaction.layers": JSON.stringify(this.layers),
          "apex.compaction.persistence.written": this.written,
          "apex.compaction.persistence.write_failed": this.writeFailed,
          "apex.compaction.evidence.results.status": this.capturePayloads
            ? "unavailable"
            : "disabled",
        });
        if (this.capturePayloads) {
          this.captureValue(
            "results",
            () =>
              Array.from(this.resultEvidence, ([position, result]) => ({
                position,
                ...result,
              })),
            RESULT_EVIDENCE_BYTES,
          );
          if (
            this.results.size > this.resultEvidence.size ||
            this.resultEvidenceFailed
          ) {
            this.span.setAttributes({
              "apex.compaction.evidence.results.status": this
                .resultEvidenceFailed
                ? "failed"
                : "truncated",
              "apex.compaction.evidence.results.reason": this
                .resultEvidenceFailed
                ? "capture_failed"
                : "result_limit",
            });
          }
        }
      }
      if (this.capturePayloads)
        this.span.setAttribute(
          "apex.compaction.evidence.capture_ms",
          this.captureMs,
        );
    });
    this.record(() => this.span.end());
    this.ended = true;
  }
}

export function beginCompaction(
  method: CompactionMethod,
  context?: CompactionContext,
): CompactionTelemetry | undefined {
  if (!context) return;
  try {
    const span = getApexTracer().startSpan("apex.context.compact", {
      attributes: {
        "apex.compaction.version": 1,
        "apex.compaction.method": method,
        "apex.compaction.trigger": context.trigger,
        "apex.compaction.estimator": "chars_div_4_v1",
        "apex.compaction.restart_depth": context.restartDepth ?? 0,
        "apex.compaction.model": context.model,
        ...(context.sessionId
          ? { "pensar.session.id": context.sessionId }
          : {}),
        ...(context.previous
          ? {
              "apex.compaction.previous_trace_id": context.previous.traceId,
              "apex.compaction.previous_span_id": context.previous.spanId,
            }
          : {}),
      },
      ...(context.previous ? { links: [{ context: context.previous }] } : {}),
    });
    if (!span.isRecording()) {
      span.end();
      return;
    }
    return new CompactionTelemetry(span, method);
  } catch {
    // Hosts own the SDK; an unavailable exporter must not prevent inference.
    return undefined;
  }
}
