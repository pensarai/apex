import { diag, SpanStatusCode } from "@opentelemetry/api";
import type {
  ReadableSpan,
  Span as SdkSpan,
  SpanProcessor,
} from "@opentelemetry/sdk-trace-base";

export const INTERRUPTED_SPAN_ATTRIBUTE = "pensar.telemetry.interrupted";
export const INTERRUPTED_ERROR_TYPE = "ApexProcessInterrupted";
export const INTERRUPTED_SPAN_REASON =
  "Apex shut down before this span completed";
const MAX_TRACKED_ACTIVE_SPANS = 10_000;

function spanKey(span: Pick<ReadableSpan, "spanContext">): string {
  const context = span.spanContext();
  return `${context.traceId}:${context.spanId}`;
}

/**
 * Tracks every recording span owned by Apex's standalone SDK so shutdown can
 * finish spans that their instrumentation still has open. OpenTelemetry only
 * queues spans for export from `onEnd`; forceFlush alone cannot recover them.
 *
 * This processor must remain first in the provider's processor list: its
 * shutdown hook is the final backstop for spans created during forceFlush,
 * before downstream processors stop accepting ended spans.
 */
export class ActiveSpanProcessor implements SpanProcessor {
  private readonly active = new Map<string, SdkSpan>();
  private overflowWarned = false;

  onStart(span: SdkSpan): void {
    if (this.active.size >= MAX_TRACKED_ACTIVE_SPANS) {
      if (!this.overflowWarned) {
        this.overflowWarned = true;
        diag.warn(
          `Apex active-span shutdown tracking reached ${MAX_TRACKED_ACTIVE_SPANS} spans; newer spans will not be retained`,
        );
      }
      return;
    }
    this.active.set(spanKey(span), span);
  }

  onEnd(span: ReadableSpan): void {
    this.active.delete(spanKey(span));
  }

  endAll(reason = INTERRUPTED_SPAN_REASON): void {
    // Spans start parent-first, so reverse insertion order closes the deepest
    // children before their parents. Copy first because span.end() calls onEnd.
    const spans = [...this.active.entries()].reverse();
    for (const [key, span] of spans) {
      try {
        if (span.isRecording()) {
          span.setAttribute(INTERRUPTED_SPAN_ATTRIBUTE, true);
          if (span.attributes["error.type"] === undefined) {
            span.setAttribute("error.type", INTERRUPTED_ERROR_TYPE);
          }
          if (span.status.code !== SpanStatusCode.ERROR) {
            span.setStatus({ code: SpanStatusCode.ERROR, message: reason });
          }
          span.end();
        }
      } catch {
        // One faulty instrumentation span must not block the remaining flush.
      } finally {
        // Delete only the copied entry. A downstream onEnd hook may start a
        // new span re-entrantly, which must survive for the shutdown backstop.
        this.active.delete(key);
      }
    }
  }

  async forceFlush(): Promise<void> {}

  async shutdown(): Promise<void> {
    this.endAll();
  }
}
