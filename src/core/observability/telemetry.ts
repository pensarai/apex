import { APICallError, type LanguageModelV3 } from "@ai-sdk/provider";
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
  | "apex.tool.repair"
  | "apex.finding.cvss"
  | "apex.finding.deduplicate"
  | "apex.finding.root-cause"
  | "apex.session.name";

export interface CreateAiTelemetryInput {
  operation: AiTelemetryOperation;
  sessionId?: string;
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

function describeFailure(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error) || String(error);
  } catch {
    return String(error);
  }
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
      const message = describeFailure(error);
      span.recordException(error instanceof Error ? error : message);
      span.setStatus({ code: SpanStatusCode.ERROR, message });
    },
  };
}

// ---------------------------------------------------------------------------
// Provider-call failure attributes. The SDK's exception events carry type,
// message, and stack but drop structured facts such as APICallError
// .statusCode; downstream trace projection retains allowlisted span
// attributes, not event payloads — so known failure facts must land on the
// provider span itself while it is still recording.
// ---------------------------------------------------------------------------

const ERROR_TYPE_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

const MIN_HTTP_STATUS = 100;
const MAX_HTTP_STATUS = 599;

function recordProviderCallFailure(error: unknown): void {
  try {
    const span = trace.getActiveSpan();
    if (!span?.isRecording()) return;
    if (error instanceof Error && ERROR_TYPE_PATTERN.test(error.name)) {
      span.setAttribute("error.type", error.name);
    }
    // statusCode is carried only by APICallError; anything that is not an
    // in-range integer stays unattributed rather than guessed.
    if (APICallError.isInstance(error)) {
      const statusCode = error.statusCode;
      if (
        typeof statusCode === "number" &&
        Number.isInteger(statusCode) &&
        statusCode >= MIN_HTTP_STATUS &&
        statusCode <= MAX_HTTP_STATUS
      ) {
        span.setAttribute("http.response.status_code", statusCode);
      }
    }
  } catch {
    // Decoration is best-effort telemetry: it must never replace the
    // provider's original thrown error.
  }
}

/**
 * Passive diagnostic wrapper around a resolved provider model. When a
 * provider call throws, the SDK's active provider span (`*.doGenerate` /
 * `*.doStream`) gains `error.type` when the error's name is identifier-like
 * (1–64 chars of `[A-Za-z0-9._-]`), and a numeric `http.response.status_code`
 * when an `APICallError` carries an integer in the 100–599 range. Return
 * values, thrown errors, and call counts pass through untouched; no messages,
 * request or response bodies, or stack traces are copied into attributes.
 */
export function withModelCallDiagnostics<T extends LanguageModelV3>(
  model: T,
): LanguageModelV3 {
  return {
    specificationVersion: model.specificationVersion,
    provider: model.provider,
    modelId: model.modelId,
    supportedUrls: model.supportedUrls,
    doGenerate: async (options) => {
      try {
        return await model.doGenerate(options);
      } catch (error) {
        recordProviderCallFailure(error);
        throw error;
      }
    },
    doStream: async (options) => {
      try {
        return await model.doStream(options);
      } catch (error) {
        recordProviderCallFailure(error);
        throw error;
      }
    },
  };
}
