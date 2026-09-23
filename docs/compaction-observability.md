# Compaction observability

Apex emits `apex.context.compact` spans when context fitting exceeds its
budget, when summarization runs, and when recovery resets to a minimal prompt.
Checks that already fit emit no compaction span. An OTLP endpoint or a host-owned
OTel provider must be configured; the compaction strategy remains unchanged.

Each span carries `apex.compaction.version = 1` and these attributes:

| Suffix under `apex.compaction.`                                                                                                 | Meaning                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `method`                                                                                                                        | `fit`, `summarize`, or `reset`                                                                                                                                             |
| `trigger`                                                                                                                       | `proactive`, `context_overflow`, or `summary_overflow`                                                                                                                     |
| `model`, `restart_depth`                                                                                                        | Requested model and existing recovery depth                                                                                                                                |
| `before.estimated_tokens`, `after.estimated_tokens`                                                                             | Message-only estimates, using `estimator = chars_div_4_v1`; not provider usage                                                                                             |
| `before.message_count`, `after.message_count`                                                                                   | Message counts at the transformation boundary                                                                                                                              |
| `context_window`, `reserved_output_tokens`, `overhead_tokens`, `system_tokens`, `safety_margin_tokens`, `message_budget_tokens` | The inputs to the existing fitting budget                                                                                                                                  |
| `truncation_enabled`                                                                                                            | Whether the session path needed for tool-output persistence was provided                                                                                                   |
| `layers`                                                                                                                        | JSON array of applied reductions, with method, threshold, and before/after token estimates; truncate thresholds are characters, snip thresholds are recent assistant steps |
| `affected_results`                                                                                                              | Distinct tool-result positions changed during fitting, not the sum across cascading passes                                                                                 |
| `fits_budget`, `modified`                                                                                                       | Fit-only results; a fitting estimate does not establish provider acceptance                                                                                                |
| `summary.max_message_chars`, `summary.max_history_chars`, `summary.max_system_chars`, `summary.max_messages`                    | Existing summarizer input limits                                                                                                                                           |
| `outcome`                                                                                                                       | `completed`, `insufficient_reduction`, `failed`, or `aborted`                                                                                                              |
| `previous_trace_id`, `previous_span_id`                                                                                         | Previous compaction in this stream's recovery chain, also represented as an OTel span link                                                                                 |

`pensar.session.id` identifies the supplied session, including subagents. The
span's trace/span IDs identify the compaction. Subsequent AI SDK model spans carry
`ai.telemetry.metadata.compactionTraceId` and `compactionSpanId`; summarizer spans
reference their current compaction. Separate agent streams never share this
mutable continuation state. The agent-stream metadata includes
`compactionTelemetryVersion = "1"`; its absence on older traces means unknown
coverage, not zero compactions. Incomplete trace capture remains incomplete even
when the producer version is known.

Compaction spans end when replacement context is ready, before the resumed
stream starts. `completed` does not mean the provider accepted the context or
the agent solved its task. Follow the linked model call and run outcome. Model
usage remains on the existing summarizer/provider spans; compaction spans carry
no billable token counters and must not be classified as model calls.

Consumers must retain the bounded metadata through their collector and artifact
projection, and preserve the model metadata links. Span events alone are not
required for this contract. A missing field is unknown, never an inferred zero.

Research evidence uses the existing `AI_TRACE_RECORD_PAYLOADS=true` setting,
subject to the host's `runWithAiPayloadCapture` override. Disabled capture does
not traverse or serialize evidence. Enabled capture adds these attributes under
`apex.compaction.evidence.`:

| Suffix                                                | Meaning                                                                                                                                                                             |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `before.json`, `after.json`                           | JSON snapshots of messages and system context at the compactor boundary; before summarization/reset also includes the original prompt                                               |
| `before.status`, `after.status`, `results.status`     | `available`, `disabled`, `truncated`, `unavailable`, or `failed`                                                                                                                    |
| `<name>.reason`, `<name>.bytes`, `<name>.limit_bytes` | Availability reason, emitted UTF-8 JSON bytes, and the producer's byte cap                                                                                                          |
| `results.json`                                        | Fit-only array of affected message/part positions, tool call IDs/names, last method, input/output/original character counts, preservation status, and local file reference if known |
| `capture_ms`                                          | Time spent capturing snapshots and serializing the affected-result list; included in compaction duration                                                                            |

Snapshots describe the transformation, before provider-specific request
normalization such as cache markers. The linked model span is authoritative for
the actual model request. The existing `apex.context.summarize` model spans
contain the summarizer's actual prompt/output and usage; these are not copied
onto the compaction span. Before snapshots include tool results that the
summarizer's text-only filter removes.

Each context snapshot is capped at 2 MiB. The affected-result list is capped at
256 entries and 256 KiB: at most 4.25 MiB of additional JSON evidence per fitting
span, before transport encoding. Capture also limits traversal to 10,000 nodes
and depth 32. A snapshot that exceeds a limit is withheld with `truncated`
status, rather than emitting invalid partial JSON. An entry-limited result list
may contain a valid subset, also marked `truncated`. Unsupported non-JSON values
are `unavailable`; getters and custom serializers are not invoked. Capture
errors are `failed` and do not change inference. A failed transformation can
have available before evidence and unavailable after evidence.

Tool-output preservation is `written`, `write_failed`, `referenced_unverified`,
or `not_persisted`. Only writes observed succeeding in this compaction are
`written`; an old truncation marker does not prove its file exists. A local file
reference does not mean the file was uploaded or is available to a consumer.
The metadata-only counters `apex.compaction.persistence.written` and
`write_failed` count actual write attempts, not repeated threshold passes.

Treat snapshot JSON, result IDs/names, and paths as payloads in collectors and
artifact projections, under the same access and retention rules as model
prompts. Preserve their statuses in metadata views. `available` describes
capture at the producer: consumers must also verify the JSON survived export
and projection (including its byte length) before declaring it available.
Existing host SDK/collector limits can still truncate or drop evidence.

This instrumentation changes no compaction thresholds, prompts, model calls,
or retry rules. Metadata costs span bookkeeping; enabled evidence additionally
costs traversal, serialization, memory, and export traffic on compaction paths.
It does not add a network flush or persistence operation. Model payload capture
and the host's exporter retain their existing behavior.

Native rollout evidence and ATIF export continue to record the actual model
boundary independently. This contract adds compaction history to OTel; it does
not add compaction events to the ATIF schema or enable native capture implicitly.
