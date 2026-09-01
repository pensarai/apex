import type { Span } from "@opentelemetry/api";

/**
 * Registry of in-flight root agent-run spans. The agent registers its root
 * span for the duration of a run; the observability runtime's shutdown ends
 * anything still registered before flushing, so an interrupted run's span
 * still exports (with whatever state it had) instead of leaking.
 */

const activeRootSpans = new Set<Span>();

export function registerActiveRootSpan(span: Span): void {
  activeRootSpans.add(span);
}

export function unregisterActiveRootSpan(span: Span): void {
  activeRootSpans.delete(span);
}

/** End every registered root span (best-effort; idempotent on spans). */
export function endAllActiveRootSpans(): void {
  for (const span of activeRootSpans) {
    try {
      span.end();
    } catch {
      // A dead span must never block process teardown.
    }
  }
  activeRootSpans.clear();
}
