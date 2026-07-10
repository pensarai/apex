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

/**
 * OTel baggage key for the execution-session id. Console's SpanProcessor copies
 * any `pensar.*` baggage entry onto every span, so setting this makes a span's
 * `pensar.session.id` the subagent's own session rather than the inherited root.
 * Must stay exactly in sync with Console's SpanProcessor.
 */
export const SESSION_BAGGAGE_KEY = "pensar.session.id";

/**
 * Run `fn` inside an OTel context whose baggage sets
 * `pensar.session.id = sessionId`, so every span opened within `fn` (the
 * subagent's `invoke_agent` span and its whole descendant subtree — model
 * streams, tool spans) carries that subagent's own execution-session id.
 *
 * Only `pensar.session.id` is overridden — `pensar.root_session.id` (and any
 * other baggage) is preserved, so the dispatched root stays the root for the
 * subtree. The override is applied only when `sessionId` is a real `ses_` id;
 * for the top-level dispatched agent (no `sessionId`, or a non-`ses_` value)
 * the active baggage is left untouched, so its spans keep `session == root`.
 */
export function withSubagentSessionBaggage<T>(
  sessionId: string | undefined,
  fn: () => T,
): T {
  // Only stamp a *pure* session id. Composite routing ids like
  // `${sessionId}-plan` / `${sessionId}-tasks` still start with `ses_` (so
  // isSessionId passes) but are not real `agent_sessions` ids — stamping one as
  // pensar.session.id would break the join. A well-formed id is `ses_<ULID>`
  // with no `-`, so a hyphen marks a derived id; those fall through and inherit
  // the parent session instead.
  if (!sessionId || !isSessionId(sessionId) || sessionId.includes("-")) {
    return fn();
  }
  const baggage = (
    propagation.getActiveBaggage() ?? propagation.createBaggage()
  ).setEntry(SESSION_BAGGAGE_KEY, { value: sessionId });
  return context.with(propagation.setBaggage(context.active(), baggage), fn);
}
