# Observability: OTel / OTLP tracing

Apex exports OpenTelemetry traces through standard OTLP/HTTP configuration.
Everything is **optional and disabled by default** — no endpoint configured,
no runtime registered, zero overhead beyond a no-op tracer.

## Quick start (any OTLP/HTTP backend)

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_SERVICE_NAME=apex-standalone
pensar
```

## Langfuse

Langfuse accepts OTLP/**HTTP** — not OTLP/gRPC. Configure:

```bash
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://cloud.langfuse.com/api/public/otel/v1/traces
OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_TRACES_HEADERS=Authorization=Basic <base64 project-key:secret>,x-langfuse-ingestion-version=4
OTEL_RESOURCE_ATTRIBUTES=langfuse.environment=production,langfuse.release=<git-sha>
AI_TRACE_RECORD_PAYLOADS=true
```

Notes:

- **Full payload mode is sensitive.** `AI_TRACE_RECORD_PAYLOADS=true` exports
  prompts, responses, reasoning, tool arguments, and tool results to the
  configured backend. That can include customer source code, credentials,
  cookies, authorization headers, attack targets, and model reasoning. It is
  off by default; turn it on only for backends you control.
- **Sampling must stay disabled** for complete run capture — Apex registers
  an always-on sampler so every root run produces one coherent trace.
- **Console owns OTel when embedding Apex.** The standalone runtime never
  registers a global provider unless a standalone entrypoint started it with
  an endpoint configured; embedded deployments (Console) provide their own SDK.
- **Standalone Apex owns OTel only when explicitly configured** via the
  `OTEL_EXPORTER_OTLP_*` variables above.

## Environment variables

| Variable                                                   | Effect                                       |
| ---------------------------------------------------------- | -------------------------------------------- |
| `OTEL_SDK_DISABLED=true`                                   | Runtime is a no-op; nothing registers        |
| `OTEL_SERVICE_NAME`                                        | Resource `service.name` (default `apex`)     |
| `OTEL_RESOURCE_ATTRIBUTES`                                 | Merged onto the resource (`k=v,k2=v2`)       |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`                       | Trace URL, verbatim (wins)                   |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                              | Generic URL; `v1/traces` appended            |
| `OTEL_EXPORTER_OTLP_HEADERS` / `..._TRACES_HEADERS`        | Export headers (specific wins, combined)     |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` / `..._OTLP_PROTOCOL` | `http/json` (default) or `http/protobuf`     |
| `AI_TRACE_RECORD_PAYLOADS=true`                            | Full payload capture (sensitive — see above) |

## What you get

Every top-level agent run is one coherent trace:

```
invoke_agent <mode>          root run (pensar.run.id, session, mode)
  ai.streamText              model call
    ai.streamText.doStream   provider call (tokens, cache, finish reason)
    ai.toolCall              tool execution (args/results in full mode)
      invoke_agent <sub>     subagent run (its own execution session id)
        ai.streamText
```

Structured JSON logs carry `trace_id`/`span_id` when written inside a span,
and `trace.jsonl` records carry a `correlation` object — connecting OTel
traces, logs, and W&B uploads.

## Failure diagnostics

Model-call failures are recorded passively on the spans the AI SDK already
emits. What each path carries on failure:

| Path                                                                | Recorded on failure                                                                                                                                       | Known limits                                                                                                    |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Helper `generateText` (structured generate, summarize, tool repair) | `ai.generateText` and `ai.generateText.doGenerate` both end with error status and an `exception` event (`exception.type`, message, stack)                 | No `error.type` span attribute; a numeric HTTP status known to the thrown error is not projected onto the spans |
| Streaming (`streamText`)                                            | A thrown provider error marks both spans; an in-stream error part is marked on the root `ai.streamText` span (the `doStream` span can complete unerrored) | Same attribute limits as the helper path                                                                        |
| Shutdown                                                            | Open spans gain `pensar.telemetry.interrupted=true` and `error.type=ApexProcessInterrupted` unless an error type is already set                           | An interruption marker is not evidence that the run was cancelled                                               |

A rejected request never generated: token attributes stay absent rather than
zero, and a generic error stays generic — nothing invents a schema or
transport diagnosis. Payload capture remains opt-in
(`AI_TRACE_RECORD_PAYLOADS`).

## Shutdown behavior

Standalone processes flush before exit on every path — normal completion,
TUI exit, SIGINT, SIGTERM, uncaught exceptions, and unhandled rejections —
with a bounded timeout (default 5s) so a hung exporter can never block
process exit. In-flight root runs are ended before the final flush so their
spans still export.
