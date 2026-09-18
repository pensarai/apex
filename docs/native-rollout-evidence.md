# Native rollout evidence

Native rollout evidence is an opt-in, run-scoped record of the model boundary.
It can emit Apex's payload-free inference-attempt events from that same
physical boundary, with the same attempt ID and retry lineage. Enabling it does
not enable telemetry payloads, alter provider options, or add a provider call.

For a standalone run, pass a fresh directory explicitly. The option is
default-off for every invocation, including resumed sessions.

```bash
pensar pentest --target https://example.test \
  --native-rollout-evidence ./evidence/run-001
```

`operator` and `targeted-pentest` accept the same option. Apex creates the
destination exclusively before an agent or model starts. Evidence and attempt
events are written immutably, and `manifest.json` is written last. A directory
without that marker is an incomplete capture. Interrupted runs retain the
files that were accepted before interruption.

## Host integration

The host creates one capture for a run, supplies a sink, and keeps the complete
run inside `capture.run`. Capture is disabled unless `enabled: true` is passed.

```ts
const capture = createNativeRolloutEvidenceCapture({
  enabled: true,
  runId,
  sink: { write: persistImmutableEvidence },
  attemptSink: { write: persistPayloadFreeAttempt },
});

await capture.run(runAgent);
const report = await capture.flush();
```

`write` receives one validated `pensar.native_rollout_evidence` version 1
envelope per physical model attempt and an abort signal for its delivery
deadline. The host chooses storage and access controls. It must await `flush`
before treating the capture report as final. A rejected write is reported as
dropped. A deadline without confirmation is reported separately as delivery
unknown because a sink that ignores the signal may still finish later. Neither
condition replaces a provider result or triggers a retry. Sinks must honor the
abort signal and use the envelope attempt ID as an idempotency key.

The optional attempt sink receives `started` and terminal inference-attempt
events for the same physical call. Terminal events carry normalized usage when
the SDK provides it. Attempt-sink rejection or timeout is diagnostic only and
cannot change the provider result, trigger another request, or suppress the
native evidence record.

The default limits are 1 MiB per content asset, 2 MiB per envelope, 32 pending
sink writes, 32 diagnostics, and 2 seconds per sink write. Callers can lower or
raise them per run. Oversized content and records remain explicit in the
envelope or capture report.

## Recorded boundary

Each envelope identifies the run, optional session, logical turn, physical
attempt, retry lineage, requested model, effective model, operation class, and
content-addressed assets. The normalized input is the `LanguageModelV3` call
after Apex and caller middleware have prepared the request. It includes the
actual prompt, tool definitions and selection, output format, sampling values,
provider options, and limits supplied to that call. A compacted call therefore
records the compacted context actually sent, without presenting discarded
history as visible context.

When the adapter exposes a serialized provider request or response body, the
envelope stores it as a separately labelled native asset. Streaming output is
collected from the exact stream parts forwarded to the caller. Raw stream
chunks are captured only when the existing call already requested them; the
collector never enables raw chunks itself. Headers and credentials are not
captured by this boundary.

Availability uses five states:

- `available`: the exact exposed value is present; empty arrays and zero values
  remain available values.
- `unsupported`: the provider or SDK boundary has no supported field.
- `omitted`: the route could expose the field but did not return it.
- `truncated`: the value crossed a capture limit; its observed hash and byte
  length are retained when available.
- `interrupted`: the stream or attempt ended before the field was complete.

Disabled capture appears only in the run-level capture report. A completed
capture report means the sink accepted every envelope; it does not imply that
every optional native field was available.

## Provider capability matrix

| Evidence                        | OpenAI chat/responses                                                                                      | Anthropic, Bedrock, Google, OpenRouter, compatible and Pensar routes |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Normalized actual call context  | Available within limits                                                                                    | Available within limits                                              |
| Serialized native request body  | Available when the adapter returns `request.body`; otherwise omitted                                       | Same                                                                 |
| Non-stream native response body | Available when the adapter returns `response.body`; otherwise omitted                                      | Same                                                                 |
| Raw streaming response chunks   | Captured only when the existing call enabled raw chunks and the adapter emitted them                       | Same                                                                 |
| Prompt token IDs                | Unsupported by the current AI SDK v3 boundary                                                              | Unsupported by the current AI SDK v3 boundary                        |
| Completion token IDs            | Unsupported by the current AI SDK v3 boundary                                                              | Unsupported by the current AI SDK v3 boundary                        |
| Completion log probabilities    | Preserved from existing `providerMetadata.openai.logprobs`; omitted when absent                            | Unsupported until a documented adapter field is added                |
| Tokenizer identity              | Unsupported by the current boundary                                                                        | Unsupported by the current boundary                                  |
| Provider-specific `extra`       | Version 1 allowlist for response ID, service tier, prediction-token counters, and returned logprob entries | Unsupported until a versioned adapter is added                       |

Apex does not request log probabilities or token IDs. A provider model can
support them while the selected SDK route still reports them as unsupported or
omitted here.

## Lifecycles and limits

Retries receive new attempt IDs and preserve the first attempt's idempotency
key, root attempt ID, previous attempt ID, and logical turn across both record
types. Direct-call failures and failures in a completed asynchronous operation
scope are recorded as terminal without waiting for run shutdown. An open
streaming operation scope retains failed attempts for a possible physical
retry, up to the configured pending-record limit. If that bound finalizes an
older failure before attribution is known, the capture report includes a
`retry_lineage_limit` diagnostic. A cancelled stream is `aborted`; a stream
error, unconsumed stream, or output-length stop is partial or interrupted. A
saved raw-stream prefix is independently marked `truncated` or `interrupted`
when later raw bytes are omitted or a terminal finish is absent. Collector
assembly, validation, queue, size, sink, and timeout failures are bounded and
reported without changing inference behavior.

In-process subagent calls include a parent session and parent tool-call ID only
when the spawning AI SDK callback supplies that exact ID. Internal or legacy
spawns without an authoritative SDK tool-call ID remain unattributed; labels,
session names, and equal run IDs are never treated as ancestry. The boundary
also cannot backfill native fields or exact model inputs from historical UI
previews, session summaries, or OTel payload-free events. Those sources remain
useful diagnostics but are not complete rollout evidence.
