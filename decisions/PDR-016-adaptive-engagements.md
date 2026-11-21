# PDR-016: Adaptive engagement coordination and landed results

## Context

A fixed set of endpoint tests cannot follow newly discovered exploit prerequisites across services. Worker completion also does not establish that the lead reviewed the evidence or that every in-scope security boundary was tested.

## Decision

An engagement seals the approved target manifest, context revision, and supplied threat-model obligations before testing. The lead creates and revises missions within that scope. Workers may add scoped subtasks and propose chain hypotheses. All initial work, retries, revisions, and subtasks share one bounded scheduler; a worker retains its slot until its resources drain.

Worker results are submissions. The lead accepts a specific attempt into an append-only landed ledger, retaining its evidence and review. Reassignment does not rewrite earlier accepted results. Coverage obligations and chain dispositions reference landed validation across their affected targets. Opening further validation reopens the associated obligation or hypothesis.

A completion response references the state and material-event revision the lead reviewed. New work or evidence invalidates that decision. Execution may end with blocked coverage, but the API and report then identify the assessment as incomplete. An absolute user deadline stops further testing and preserves submitted results and unresolved coverage; recovery cannot extend it.

The shared board and directed mail retain reusable observations, including prerequisites that do not qualify as standalone findings. The findings registry remains the authoritative vulnerability record described in PDR-005.

## Runtime ownership

Apex provides the local runner and the shared planning, coordination, acceptance, and assessment contracts. Hosted execution must persist those records in product storage and rebuild agent hooks for each independently recoverable attempt. Console uses its existing durable node kernel, leased tool backends, and execution-event translator. Existing recorded jobs retain their prior execution contract during rollout.

## Consequences

- The lead can investigate chains across approved surfaces without silently widening authorization.
- Known obligations and discovered hypotheses have explicit, evidence-backed outcomes. This does not certify discovery of every possible vulnerability.
- gRPC missions remain single-target; the lead coordinates cross-protocol chains through separate validation missions.
- Local coordination state is version 2. Version 1 state has no lead-acceptance history and is rejected rather than treated as landed evidence.
