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
