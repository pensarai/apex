import {
  type Span,
  SpanStatusCode,
  type Tracer,
  trace,
} from "@opentelemetry/api";
import { shouldRecordAiPayloads } from "./index";

/**
 * Structurally the AI SDK's `TelemetrySettings` (the package does not
 * re-export the type). Passed as `experimental_telemetry` on model calls.
 */
export interface AiTelemetrySettings {
  isEnabled: boolean;
  recordInputs: boolean;
  recordOutputs: boolean;
  /** Stable, low-cardinality operation identifier (`apex.<area>.<verb>`). */
  functionId: string;
  metadata?: Record<string, string>;
}

/** Stable operation identifiers for every model-call helper. */
export type AiTelemetryOperation =
  | "apex.agent.stream"
  | "apex.structured.generate"
  | "apex.context.summarize"
  | "apex.tool.repair";

export interface CreateAiTelemetryInput {
  operation: AiTelemetryOperation;
  sessionId?: string;
  runId?: string;
  agentId?: string;
}

/**
 * One builder for every model call's telemetry — identical payload policy
 * everywhere. Full payload capture (`recordInputs`/`recordOutputs`) is
 * opt-in via `AI_TRACE_RECORD_PAYLOADS=true` and never defaults on.
 *
 * ⚠️ Full mode exports sensitive data to the configured OTLP backend,
 * including customer source code, credentials, cookies, authorization
 * headers, attack targets, and model reasoning. Off by default.
 */
export function createAiTelemetrySettings(
  input: CreateAiTelemetryInput,
): AiTelemetrySettings {
  const recordPayloads = shouldRecordAiPayloads();
  const metadata: Record<string, string> = {};
  if (input.sessionId) metadata.sessionId = input.sessionId;
  if (input.runId) metadata.runId = input.runId;
  if (input.agentId) metadata.agentId = input.agentId;
  return {
    isEnabled: true,
    recordInputs: recordPayloads,
    recordOutputs: recordPayloads,
    // Model ids belong in span attributes (ai.model.id), never in the
    // operation name — a per-model functionId is unbounded cardinality.
    functionId: input.operation,
    ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
  };
}

// ---------------------------------------------------------------------------
// Generation span tracker — the AI SDK completes error-part runs normally,
// so its root generation span exports without error status. A forwarding
// tracer captures that span's handle so the stream wrapper can mark it
// failed. Not a span processor; the spans are the SDK's own.
// ---------------------------------------------------------------------------

export interface GenerationSpanTracker {
  /** Forwarding tracer — pass as `experimental_telemetry.tracer`. */
  readonly tracer: Tracer;
  /** Record the failure on the captured root generation span (no-op if none
   *  or already marked by the SDK's thrown-error handling). */
  markFailed(error: unknown): void;
}

export function createGenerationSpanTracker(): GenerationSpanTracker {
  const inner = trace.getTracer("ai");
  let rootSpan: Span | null = null;
  // The SDK creates its spans via startActiveSpan (recordSpan); capture the
  // root generation span by wrapping the caller's callback.
  const tracer = {
    startSpan: (
      name: string,
      options?: Parameters<Tracer["startSpan"]>[1],
      context?: Parameters<Tracer["startSpan"]>[2],
    ) => {
      const span = inner.startSpan(name, options, context);
      if (name === "ai.streamText") rootSpan = span;
      return span;
    },
    // The API resolves overloads by arguments.length — forward with the
    // caller's exact arity and wrap the callback to capture the span.
    startActiveSpan: (name: string, ...rest: unknown[]) => {
      const callback = rest[rest.length - 1] as (
        span: Span,
        ...r: unknown[]
      ) => unknown;
      const capture = (span: Span, ...restArgs: unknown[]) => {
        if (name === "ai.streamText") rootSpan = span;
        return callback(span, ...restArgs);
      };
      const forwardArgs = [...rest.slice(0, -1), capture];
      return (
        inner.startActiveSpan as unknown as (
          this: unknown,
          n: string,
          ...a: unknown[]
        ) => unknown
      ).call(inner, name, ...forwardArgs);
    },
  } as unknown as Tracer;
  let marked = false;
  return {
    tracer,
    markFailed(error: unknown) {
      const span = rootSpan;
      if (!span || marked) return;
      marked = true;
      if (error instanceof Error) {
        span.recordException(error);
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
      } else {
        span.setStatus({ code: SpanStatusCode.ERROR });
      }
    },
  };
}
