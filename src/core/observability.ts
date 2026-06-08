/**
 * OpenTelemetry helpers. The tracer is a no-op unless the host process
 * registers an OTel SDK; payload capture is off unless
 * `AI_TRACE_RECORD_PAYLOADS=true`.
 */

import { type Tracer, trace } from "@opentelemetry/api";

export function getApexTracer(): Tracer {
  return trace.getTracer("apex");
}

export function shouldRecordAiPayloads(): boolean {
  return process.env.AI_TRACE_RECORD_PAYLOADS === "true";
}
