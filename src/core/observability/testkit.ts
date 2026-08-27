import { context, trace } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  type ReadableSpan,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";

/**
 * In-memory OTel harness for observability tests. Registers a real
 * tracer provider + async context manager globally so the AI SDK's built-in
 * instrumentation emits spans, and collects them for assertion. Always call
 * `shutdown()` in afterEach — it resets the global provider and context
 * manager so other tests see the no-op SDK.
 */
export interface OtelTestHarness {
  readonly exporter: InMemorySpanExporter;
  readonly provider: BasicTracerProvider;
  getFinishedSpans(): ReadableSpan[];
  shutdown(): Promise<void>;
}

export function startOtelTestHarness(): OtelTestHarness {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  const contextManager = new AsyncLocalStorageContextManager();
  contextManager.enable();

  // BasicTracerProvider has no register() (that's NodeTracerProvider) —
  // wire the globals directly.
  trace.setGlobalTracerProvider(provider);
  context.setGlobalContextManager(contextManager);

  return {
    exporter,
    provider,
    getFinishedSpans: () => exporter.getFinishedSpans(),
    async shutdown() {
      await provider.forceFlush();
      await provider.shutdown();
      contextManager.disable();
      // Reset globals so later tests observe a no-op SDK.
      trace.disable();
      context.disable();
    },
  };
}

/** Find the first finished span by name, failing loudly when absent. */
export function requireSpan(
  spans: readonly ReadableSpan[],
  name: string,
): ReadableSpan {
  const span = spans.find((s) => s.name === name);
  if (!span) {
    throw new Error(
      `expected span ${JSON.stringify(name)}; got: ${spans.map((s) => s.name).join(", ")}`,
    );
  }
  return span;
}

/** All finished spans by name. */
export function spansNamed(
  spans: readonly ReadableSpan[],
  name: string,
): ReadableSpan[] {
  return spans.filter((s) => s.name === name);
}

/**
 * The span a given span was a direct child of. SDK 2.x carries the parent as
 * `parentSpanContext` (a SpanContext), not the legacy `parentSpanId` string.
 */
export function parentOf(
  spans: readonly ReadableSpan[],
  span: ReadableSpan,
): ReadableSpan | undefined {
  const parentId = span.parentSpanContext?.spanId;
  if (!parentId) return undefined;
  return spans.find((s) => s.spanContext().spanId === parentId);
}
