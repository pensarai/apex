# PDR-009: Opt-in transactional run admission

## Context

A session groups assessment artifacts, but does not identify a single admitted execution. Session JSON writes and in-process locks cannot atomically decide which of two processes may execute the same request. Retrying a start command after a lost acknowledgement can otherwise start duplicate work.

## Decision

Add an opt-in recorded local run with an explicit immutable input specification, session reference, execution attempt identity, and last committed status. Commit admission before creating the session or calling the agent. Only the caller that creates the record may execute; duplicate admissions return the record, and conflicting inputs fail. A process lost after admission leaves an inspectable record and cannot be automatically restarted.

The public API accepts an injectable `RunStore`. The local adapter uses SQLite transactions through Bun's built-in SQLite or Node's built-in SQLite. The new local adapter requires Bun or Node 22.13+; this does not change the package-wide engine floor or the legacy command paths. Runtime-specific modules load only when the caller opens this adapter.

The store owns admission and status. Session files retain their existing assessment-artifact authority. These records do not yet make conversation, tools, approvals, artifacts, or provider attempts recoverable. Follow-up changes must establish those persistence boundaries before enabling resume.

## Rationale

A database transaction supplies atomic admission and cross-process exclusion without implementing a lock-reclamation protocol. SQLite also provides a place for later context and operation commits without moving to full event sourcing. Keeping persistence behind a small contract leaves managed storage to the host without adding a second scheduler or retry authority.

New behavior is opt-in and has a narrower supported path: a fresh local solo agent with declared tools and scope and a built-in catalog model. Custom-provider configuration and dynamic Hoonify model IDs need an explicit versioned configuration contract before admission can freeze them. This keeps existing TUI/API callers intact and allows the admission work to land independently of the execution-owner refactor.

## Alternatives considered

- **Reuse session JSON writes:** their process-local locks and direct overwrites do not supply the required admission transaction.
- **Build an atomic filesystem protocol:** feasible for a single record, but stale claims, multi-record commits, and later recovery would become Apex's responsibility.
- **Add a native SQLite dependency:** retains older Node support but adds packaging and native-addon maintenance across npm and standalone binaries. Built-ins suffice for the opt-in path.
- **Raise the package-wide Node minimum:** unnecessary for this feature; older runtimes can continue using the legacy commands.
- **Add a daemon or scheduler:** neither supplies safe admission or crash recovery by itself, and neither is required for this slice.

## Consequences

- Duplicate starts do not create duplicate agent executions.
- Unsupported versions, corrupt records, and failed critical writes fail explicitly.
- The run's status is historical; `running` does not establish worker liveness.
- Admission can survive while execution never started. Recovery remains deliberately unavailable until unknown tool outcomes and reconstruction prerequisites can be handled.
- The new local adapter has a newer Node requirement than legacy Apex commands. Its native APIs must be exercised in Node, Bun, and compiled-binary checks.

See [recorded runs](../docs/recorded-runs.md) for the supported path and smoke checks. The runtime availability boundaries come from the [Node SQLite documentation](https://nodejs.org/api/sqlite.html) and [Bun SQLite documentation](https://bun.sh/docs/runtime/sqlite).
