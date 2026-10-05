# PDR-013: Persist recorded-run control and approvals

## Context

An in-memory cancellation signal or approval promise disappears with its process. A second client cannot reliably distinguish a requested stop from a stopped executor, and a lost approval must never authorize a tool.

## Decision

Enroll control state before recorded execution. Store explicit pause/stop intent with a revision for compare-and-set commands. Stop dominates pause and denies pending approvals transactionally. Dispatch reservations check intent in the same transaction that accepts work. Requests arriving after reservation cannot undo already accepted effects.

Pause is cooperative. It blocks new dispatch at a boundary while accepted work may finish. A saved `paused` status is an executor acknowledgement, not proof that external effects were rolled back. Stop also propagates to the executor's abort signal. Upstream cancellation persists stop before that signal is delivered.

An optional admitted `approval.requiredTools` policy requires a durable decision for each matching validated call. The request binds run, owner, tool-call ID, input, scope/spec digest, and context. Approval precedes the accepted tool intent; pending approval never falsely claims dispatch. A denial produces a deterministic blocked result. Missing clients and restarts do not resolve requests.

Keep the existing TUI ApprovalGate unchanged. The recorded path uses its own store-backed controller with the same dispatch seams. Critical storage failures remain distinct from control interruptions and cannot be reported as a successful pause.

## Tradeoffs

- Local clients poll persisted state; no daemon, RPC transport, scheduler, or event broker is needed yet.
- Waiting approvals have no implicit timeout. An admitted absolute deadline or explicit stop ends the wait.
- Schema version 5 adds control and approval tables. Older runs remain readable and have no fabricated control enrollment.
- This slice adds pause and decision persistence, not resume or ownership transfer. The recovery slice must validate the saved state and prove exclusive execution before clearing pause.
