/**
 * Vendor-neutral OpenTelemetry helpers for Apex.
 *
 * Apex depends only on `@opentelemetry/api`. The tracer is a no-op unless
 * the host process registers an OTel SDK. Payload capture (prompts, tool
 * I/O) is off by default; set `AI_TRACE_RECORD_PAYLOADS=true` to enable.
 */

import { type Tracer, trace } from "@opentelemetry/api";

export function getApexTracer(): Tracer {
  return trace.getTracer("apex");
}

export function shouldRecordAiPayloads(): boolean {
  return process.env.AI_TRACE_RECORD_PAYLOADS === "true";
}
