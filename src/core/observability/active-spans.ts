import { SpanStatusCode } from "@opentelemetry/api";
import type {
  ReadableSpan,
  Span as SdkSpan,
  SpanProcessor,
} from "@opentelemetry/sdk-trace-base";

export const INTERRUPTED_SPAN_ATTRIBUTE = "pensar.telemetry.interrupted";
export const INTERRUPTED_SPAN_REASON =
  "Apex shut down before this span completed";

function spanKey(span: Pick<ReadableSpan, "spanContext">): string {
  const context = span.spanContext();
  return `${context.traceId}:${context.spanId}`;
}

/**
 * Tracks every recording span owned by Apex's standalone SDK so shutdown can
 * finish spans that their instrumentation still has open. OpenTelemetry only
 * queues spans for export from `onEnd`; forceFlush alone cannot recover them.
 */
export class ActiveSpanProcessor implements SpanProcessor {
  private readonly active = new Map<string, SdkSpan>();

  onStart(span: SdkSpan): void {
    this.active.set(spanKey(span), span);
  }

  onEnd(span: ReadableSpan): void {
    this.active.delete(spanKey(span));
  }

  endAll(reason = INTERRUPTED_SPAN_REASON): void {
    // Spans start parent-first, so reverse insertion order closes the deepest
    // children before their parents. Copy first because span.end() calls onEnd.
    const spans = [...this.active.values()].reverse();
    for (const span of spans) {
      if (!span.isRecording()) continue;
      try {
        span.setAttribute(INTERRUPTED_SPAN_ATTRIBUTE, true);
        if (span.status.code !== SpanStatusCode.ERROR) {
          span.setStatus({ code: SpanStatusCode.ERROR, message: reason });
        }
        span.end();
      } catch {
        // One faulty instrumentation span must not block the remaining flush.
      }
    }
    this.active.clear();
  }

  async forceFlush(): Promise<void> {}

  async shutdown(): Promise<void> {
    this.endAll();
  }
}
