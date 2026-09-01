/**
 * OpenTelemetry helpers. The tracer is a no-op unless the host process
 * registers an OTel SDK; payload capture is off unless
 * `AI_TRACE_RECORD_PAYLOADS=true`.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { context, propagation, type Tracer, trace } from "@opentelemetry/api";
import { isSessionId } from "../id/id";

export function getApexTracer(): Tracer {
  return trace.getTracer("apex");
}

/**
 * Run-scoped override for AI payload capture. The durable runtime is
 * multi-tenant (one process serves many workspaces concurrently), so payload
 * capture cannot be a process-wide env toggle without cross-tenant races. Each
 * run binds its own value here and {@link shouldRecordAiPayloads} reads it
 * before falling back to the env.
 */
const aiPayloadCaptureStore = new AsyncLocalStorage<boolean>();

/**
 * Bind AI payload capture for the duration of `fn`, overriding the
 * `AI_TRACE_RECORD_PAYLOADS` env for that async context only.
 * @public Consumed by Console's durable agent runtime for per-workspace gating.
 */
export function runWithAiPayloadCapture<T>(enabled: boolean, fn: () => T): T {
  return aiPayloadCaptureStore.run(enabled, fn);
}

export function shouldRecordAiPayloads(): boolean {
  const override = aiPayloadCaptureStore.getStore();
  if (override !== undefined) return override;
  return process.env.AI_TRACE_RECORD_PAYLOADS === "true";
}

export {
  registerActiveRootSpan,
  unregisterActiveRootSpan,
} from "./active-root-spans";
export {
  type AiTelemetryOperation,
  type AiTelemetrySettings,
  type CreateAiTelemetryInput,
  type GenerationSpanTracker,
  createAiTelemetrySettings,
  createGenerationSpanTracker,
} from "./telemetry";

/**
 * OTel baggage key for the execution-session id. Console's SpanProcessor copies
 * `pensar.*` baggage onto every span — must stay in sync with it.
 */
export const SESSION_BAGGAGE_KEY = "pensar.session.id";

/**
 * Run `fn` inside an OTel context that overrides `pensar.session.id` with
 * `sessionId` (only that key — `pensar.root_session.id` is preserved), so the
 * subagent's span subtree carries its own execution-session id. No-ops unless
 * `sessionId` is a real `ses_` id.
 */
export function withSubagentSessionBaggage<T>(
  sessionId: string | undefined,
  fn: () => T,
): T {
  // Composite routing ids (`${ses_}-plan`) pass isSessionId but aren't real
  // agent_sessions ids; the hyphen marks them derived — reject to protect the join.
  if (!sessionId || !isSessionId(sessionId) || sessionId.includes("-")) {
    return fn();
  }
  const baggage = (
    propagation.getActiveBaggage() ?? propagation.createBaggage()
  ).setEntry(SESSION_BAGGAGE_KEY, { value: sessionId });
  return context.with(propagation.setBaggage(context.active(), baggage), fn);
}

/**
 * The active span's correlation ids, when a valid recording span is active.
 * Null outside spans (or under a no-op SDK) — callers skip the fields.
 */
export function getActiveTraceCorrelation(): {
  traceId: string;
  spanId: string;
} | null {
  const spanContext = trace.getSpan(context.active())?.spanContext();
  if (!spanContext || !trace.isSpanContextValid(spanContext)) return null;
  return { traceId: spanContext.traceId, spanId: spanContext.spanId };
}
