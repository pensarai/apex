import {
  type Attributes,
  type Span,
  type SpanContext,
  SpanStatusCode,
} from "@opentelemetry/api";
import { getApexTracer } from "../observability";

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

export class CompactionTelemetry {
  private ended = false;
  private readonly results = new Set<string>();
  private readonly layers: CompactionLayer[] = [];
  readonly link: CompactionLink;

  constructor(
    private readonly span: Span,
    private readonly method: CompactionMethod,
  ) {
    this.link = span.spanContext();
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

  result(key: string): void {
    this.record(() => this.results.add(key));
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
        ...(this.method === "fit"
          ? {
              "apex.compaction.affected_results": this.results.size,
              "apex.compaction.layers": JSON.stringify(this.layers),
            }
          : {}),
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
    if (!span.isRecording()) return;
    return new CompactionTelemetry(span, method);
  } catch {
    // Hosts own the SDK; an unavailable exporter must not prevent inference.
    return undefined;
  }
}
