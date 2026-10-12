# PDR-015: Optional independent local workers

**Status:** Accepted

**Date:** 2026-10-05

## Context

Recorded runs can recover supported checkpoints after executor loss, but their foreground process still belongs to the terminal that launched it. Closing a client should not imply stopping the assessment. Detachment must preserve the existing execution lock, durable controls, and conservative recovery rules.

## Decision

Offer opt-in detached hosting for recorded runs on macOS and Linux. One local worker hosts one execution invocation. The launcher starts the same Apex executable independently of its terminal, and connects through a private Unix socket. Embedded and foreground execution remain available.

The run database remains authoritative. The worker calls the existing start or resume API; a separate OS-released lock protects socket ownership, while the existing execution lock protects agent execution. Recovery commands bind the expected previous execution attempt and validate it again under that execution lock.

Clients read atomic replacement snapshots and issue existing revision-bound controls. A bounded long poll reports changes; its worker-scoped cursor is disposable observation state, not a durable event log. Disconnecting a request affects observation only. Worker termination and explicit stop remain separate operations.

An idle worker exits after a bounded startup window. After execution settles it briefly serves the final state, then exits. Saved state remains inspectable without a running worker. Replacing a dead worker requires explicit recovery and does not bypass any missing-state or unknown-effect blocker.

## Rationale

Independent processes solve terminal lifetime without requiring a global daemon or service installation. Unix filesystem permissions provide a local access boundary without exposing a network port. Existing transactional state supports multiple observers without a second run-state implementation.

Replacement snapshots avoid retaining an unbounded token/event replay buffer. Clients can reconstruct their view from committed state after reconnecting; live per-token display is not a guarantee of this first hosting slice.

## Alternatives considered

- A global daemon creates another service to supervise before one is needed.
- PID files cannot establish execution or socket ownership after PID reuse.
- Treating connection failure as proof of worker death could unlink a live endpoint.
- Automatic retry of start/resume after a lost acknowledgement could hide an uncertain handoff.
- A persisted event stream duplicates state transitions without a current consumer requirement.

## Consequences

Closing the launching client no longer ends a detached execution. Worker crashes still require explicit same-environment recovery. Generic shell reattachment, environment restoration, managed scheduling, and expanded workflow recovery are outside this change.

Detached hosting initially requires macOS/Linux and a local filesystem with working SQLite locks. The private worker log may contain assessment data. Protocol incompatibility, oversized snapshots, and startup failures surface explicitly; the launcher does not kill a process based on a PID hint or silently retry mutations.
