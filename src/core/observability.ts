/**
 * Lightweight, vendor-neutral OpenTelemetry helpers for Apex.
 *
 * Apex emits OpenTelemetry spans for agent runs, LLM calls, and tool
 * executions, but depends only on `@opentelemetry/api` — the small,
 * vendor-neutral OTel API surface that is a no-op unless the host process
 * registers an OpenTelemetry SDK as the global tracer provider. This means:
 *
 *   - Run `apex` standalone (CLI): `trace.getTracer(...)` returns the
 *     built-in `NoopTracer`. Spans created here are no-ops. Zero overhead;
 *     no data leaves the process.
 *   - Run Apex inside a host process that registered `@sentry/node` (or
 *     `@opentelemetry/sdk-node` with any OTLP exporter): the spans flow
 *     through whichever backend the host configured. Apex doesn't know or
 *     care which backend.
 *
 * Whether AI SDK telemetry includes prompt / tool I/O content is controlled
 * by `AI_TRACE_RECORD_PAYLOADS`. Default off — shape-only emission (model,
 * tokens, latency, tool names) — which keeps customer source code, scraped
 * page contents, and credentials out of any backend Apex's host wired up.
 *
 * Hosts (e.g. Pensar Console) set this env var alongside any backend-side
 * privacy gate (e.g. Sentry's `SENTRY_AI_RECORD_PAYLOADS`) so the policy
 * stays coherent end-to-end.
 */

import { trace, type Tracer } from "@opentelemetry/api";

/**
 * Returns the `apex` tracer. Safe to call from anywhere — no SDK
 * registration required; falls back to a no-op tracer.
 */
export function getApexTracer(): Tracer {
  return trace.getTracer("apex");
}

/**
 * Whether AI SDK telemetry should record prompts and tool I/O. Off by
 * default. Set `AI_TRACE_RECORD_PAYLOADS=true` to enable.
 */
export function shouldRecordAiPayloads(): boolean {
  return process.env.AI_TRACE_RECORD_PAYLOADS === "true";
}
