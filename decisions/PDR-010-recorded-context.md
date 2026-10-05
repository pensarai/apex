# PDR-010: Commit context before selecting it

## Context

Agent transcripts are debounced compatibility exports. They can lag execution, contain synthetic closures after interruption, or combine a stale prefix with a compacted conversation. They cannot be the authority for later recovery.

## Decision

For recorded runs, commit canonical model input before dispatch and canonical conversation after each completed step. Store a base for each context epoch and ordered append deltas within that epoch. Rewrites, including compaction, open an epoch only after its transaction commits. Validate the owning execution attempt and expected revision on every write.

The recorder latches critical persistence failures. The next model dispatch checks it, and agent finalization drains it: the AI SDK can swallow step-callback exceptions, so throwing from a callback alone does not enforce this boundary. Legacy callers retain their existing behavior.

Commit evidence references with context. Existing domain files remain authoritative; references bind their session location, relative path, size, and hash. Missing or modified evidence is explicit at inspection. Retain references to deleted files instead of silently dropping them. Transcript and telemetry exports are projections, not an alternative writer of canonical context.

## Tradeoffs

- Base plus deltas avoids storing a full conversation for every growing turn. This is a context journal, not full application event sourcing.
- Hashing existing evidence adds work at checkpoint boundaries. It supplies inspection now without migrating every domain writer or copying all artifacts into the database.
- References cannot restore a deleted environment, and a completed conversation step does not settle every external tool effect. Tool journaling, safe recovery, and managed storage remain separate work.
- Store migrations are transactional and forward-only. Older executors fail explicitly on a newer store schema.

No resume command is enabled by this decision.
