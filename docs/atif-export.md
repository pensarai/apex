# ATIF trajectory export

Apex converts only validated `pensar.native_rollout_evidence` version 1 records
into ATIF. It does not call a model or provider, replay a tool, reconstruct
missing payloads from telemetry, or read historical UI projections.

The converter targets
[ATIF-v1.8 at revision `88fdbc9d42e907c0414654f041ece5eaf798f538`](https://github.com/harbor-framework/harbor/blob/88fdbc9d42e907c0414654f041ece5eaf798f538/rfcs/0001-trajectory-format.md).
Both values are pinned in the bundle manifest.

## Pure API

```ts
const bundle = serializeAtifExportBundle({
  sources: recordedEvidenceSources,
  rootSourceId,
  agent: { name: "apex", version: apexVersion },
  exporter: { name: "apex-native-evidence", version: exporterVersion },
  independentValidation,
});
```

Every source supplies an immutable ID, its exact bytes, SHA-256 digest, and byte
length. The converter validates that identity and the native evidence schema
before conversion. A bundle accepts at most 512 sources and 64 MiB of source
bytes. Callers must split larger exports into separately rooted bundles.

`serializeAtifExportBundle` returns:

- one producer-neutral `evalgate.trajectory-bundle` version 1 manifest;
- ATIF documents grouped by run-scoped ATIF `session_id`;
- a sorted file set containing `manifest.json`, individual ATIF documents,
  content-addressed assets, and the exact source evidence files;
- SHA-256 and byte length for every file.

The library writer accepts the result without interpreting Apex fields:

```ts
type WriteImmutableTrajectoryBundle = (input: {
  manifest: TrajectoryBundleManifestV1;
  files: readonly AtifBundleFile[];
}) => Promise<{ artifactId: string }>;
```

It persists each `file.bytes` at `file.path`, verifies `sha256` and
`sizeBytes`, and publishes the immutable artifact only after all files succeed.
The standalone `pensar export-trajectory` command performs the same bounded
validation and writes `manifest.json` last to a fresh destination. See
[`trajectory-export-command.md`](./trajectory-export-command.md) for its input
contract and commit-marker semantics.

## Mapping and provenance

Each physical inference attempt becomes one ATIF document. Its exact normalized
model-visible prompt is emitted as copied context, followed by one non-copied
agent step for the recorded output. Retry order within a session is represented
with `continued_trajectory_ref`. Attempt, turn, segment, operation, requested
and effective model, run, source file, and boundary availability remain in
versioned `extra` fields or the neutral manifest. When captured child evidence
has an authoritative parent session and AI SDK tool-call ID, the original
parent call receives exactly one resolvable `subagent_trajectory_ref`. Missing
or contradictory attribution is a diagnostic rather than inferred ancestry.

Text, exposed reasoning, parallel tool calls, tool results, usage, supported
OpenAI log probabilities, and captured image/audio bytes are mapped when their
recorded shapes are valid. Provider request and response bodies remain
content-addressed source assets even when ATIF has no native field for them.
External media URLs remain references and make transcript completeness partial
because their bytes are not archived in the bundle.

Invalid or unsupported fields stay in the exact source evidence and produce a
diagnostic instead of an invented ATIF value. Native sampling availability is
counted independently from transcript completeness. Missing optional token IDs,
log probabilities, tokenizer identity, or provider extras therefore remain
honest without making an otherwise complete transcript partial.

## Validation and eligibility

The built-in validator checks the pinned structural shape, step ordering,
source-specific fields, ISO timestamps, metric alignment, tool-call identity,
and embedded subagent references. Bundle validation additionally checks root,
continuation, local media, and external trajectory references. An injected
independent validator result is recorded separately; when none is supplied the
manifest says `not_run`.

ATIF validity does not assert training readiness. Version 1 marks SFT ineligible
because per-attempt source evidence cannot establish which copied context is a
new supervised example. It marks RL ineligible because the boundary does not
provide an attributable reward, policy revision, or trainer mask contract, even
when token IDs or log probabilities are available.

Internal or legacy spawns without an authoritative AI SDK tool-call ID cannot
produce a parent/subagent link. The native boundary also does not expose exact
token IDs on current routes, tokenizer identity, grading revision, reward, or
reuse permission. The exporter reports these gaps and never infers ancestry or
training consent from labels, session names, OTel spans, or provider model
metadata.
