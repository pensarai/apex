/**
 * OpenTelemetry helpers. The tracer is a no-op unless the host process
 * registers an OTel SDK; payload capture is off unless
 * `AI_TRACE_RECORD_PAYLOADS=true`.
 */

import { context, propagation, type Tracer, trace } from "@opentelemetry/api";
import { isSessionId } from "./id/id";

export function getApexTracer(): Tracer {
  return trace.getTracer("apex");
}

export function shouldRecordAiPayloads(): boolean {
  return process.env.AI_TRACE_RECORD_PAYLOADS === "true";
}

export function shouldEnableAiTelemetry(): boolean {
  return process.env.AGENT_TRACES_ENABLED !== "false";
}

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
