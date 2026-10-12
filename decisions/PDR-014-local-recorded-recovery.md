# PDR-014: Explicit recovery of recorded local runs

**Status:** Accepted

**Date:** 2026-10-05

## Context

Recorded context, tool receipts, and durable controls survive process loss, but surviving records alone do not prove that execution can safely continue. A second executor must not race a live one, repeat an uncertain effect, or reset limits.

## Decision

Add explicit same-environment recovery to the opt-in recorded-run path. Fresh runs enroll a protocol while holding a per-run SQLite execution lock. Process loss releases that lock; a recovery caller validates the saved state and atomically claims a new execution attempt. Existing runs without enrollment stay inspection-only.

Reuse the existing agent and inference/tool/context recorders for both fresh and resumed execution. Resume supplies the saved effective prompt and conversation, seeds the context revision, and retains all previous model reservations, tool receipts, controls, and evidence. A completed tool receipt can reconstruct an eligible interrupted exchange without dispatching its operation again. Unknown effects, unsupported provider continuity, shell use, missing artifacts, and unreconstructible retry counters block recovery.

## Rationale

The logical run is distinct from its execution attempt. A dedicated per-run lock establishes local exclusion without holding a transaction on the run database during model execution. Durable ownership checks reject stale writers; client control writes remain available. An explicit claim record makes repeated recovery attempts auditable, including a crash during recovery itself.

Filesystem identity and version checks bound this first implementation to the original environment. They do not claim environment snapshots, exact provider-stream replay, or globally exactly-once side effects.

## Alternatives considered

- PID files or operator assertions of death cannot prove exclusive execution.
- Time-based leases require fencing external effects and a worker supervisor; neither is needed for this local slice.
- Replaying incomplete calls could repeat target mutations.
- Serializing the process heap or shell cannot replace explicit reconstruction semantics.
- A daemon would improve detachment but would not by itself solve recovery correctness.

## Consequences

The opt-in local path can recover common checkpoint/receipt crash windows while preserving its limits. The same run can have multiple execution attempts, but only one lock holder. Recovery remains deliberately unavailable for several common workflows, including shell use and some interrupted provider exchanges. Managed recovery still needs shared persistence, environment reconciliation, worker ownership, and Console integration.
