# Engagement lead: production reliability gap plan

Date: 2026-09-13

Branch reviewed: `codex/harness-engagement-lead`
Status: proposed follow-up work; no implementation or deployment changes approved.

Related: [grounding and mission progress plan](ENGAGEMENT-LEAD-PRODUCTION-PLAN.md) covers read-only threat-model access through code mode, reviewed objective consolidation, and mission-centric UI tracking.

## Direction

Keep the architecture in [PDR-010](decisions/PDR-010-engagement-lead.md). Cairn offers useful reliability ideas, but its benchmark performance does not establish that replacing Apex's orchestration would improve production.

Preserve deterministic coverage and completion, restricted planning, finding validation, and scoped evidence checks. Make focused changes to existing state and reporting paths; do not introduce a second orchestration system or graph database.

## Priority 1: crash-safe handoff delivery

**Observed gap:** `AgentMailbox.take()` advances and persists the recipient cursor before the recipient durably records the returned messages. A crash between those operations can suppress redelivery. The original mailbox record remains stored; this is a delivery gap, not deletion of the record.

Relevant code: [AgentMailbox](src/core/workflows/engagementState.ts), [lead consumption](src/core/workflows/engagementLead.ts), and [worker consumption](src/core/workflows/engagementTools.ts).

Proposed scope:

- Separate reading pending messages from acknowledging durable receipt.
- Acknowledge only after the recipient's persisted transcript or checkpoint contains the message.
- Use stable message IDs to make replay idempotent. Do not claim exactly-once execution of downstream actions.
- Keep the existing mailbox and persistence architecture; first inspect all callers and existing write boundaries.

Acceptance checks:

- A crash after reading but before durable receipt leaves the message available on restart.
- A crash after durable receipt but before acknowledgement does not duplicate the message in recipient state.
- Failed persistence never advances acknowledgement.
- Recipient isolation and message ordering remain intact.

## Priority 2: preserve evidence provenance end to end

**Observed gap:** worker results carry structured evidence, but coordination coverage stores references as `toolName:toolCallId` strings, dropping the description and explicit execution scope from that representation.

Relevant code: [evidence validation](src/core/workflows/fastStrikeEvidence.ts), [coverage conversion](src/core/workflows/engagementTools.ts), and [persisted state](src/core/workflows/engagementState.ts).

Proposed scope:

- Preserve structured observation references and execution scope through checkpoints and reporting, with links to existing artifacts where available.
- Keep model claims distinct from validated evidence. A valid reference alone does not prove the claim's substantive impact.
- Define backward-compatible handling for existing string references; surface missing provenance rather than fabricating it.
- Reuse existing evidence and artifact storage. Avoid adding a generic knowledge-graph abstraction.

Acceptance checks:

- Checkpoint round trips preserve reference identity, scope, and description.
- Report references resolve to the intended persisted observation or artifact.
- Missing, mismatched, failed, and cross-scope references remain rejected or explicitly unresolved.
- Legacy checkpoints remain readable without silently upgrading unverified references into verified evidence.

## Deferred ideas

- **Additional summarization after interruption:** Apex already preserves interrupted transcripts and incremental grouped coverage. First establish from traces that reportable results are being lost. Any later reporting-only phase must have tools disabled, respect cancellation, and leave incomplete work incomplete.
- **State-change-driven replanning:** measure redundant coordinator calls before changing scheduling.
- **Cairn orchestration transplant:** no bootstrap/reason/explore rewrite, CLI-worker replacement, new lease infrastructure, or model-decided completion based on leaderboard performance alone.

## Review caveats and verification

- [Tencent's public metadata](https://tsecbench.zc.tencent.com/api/v1/leaderboard/agent/12662) reported `Cairn_Y` at rank 1, score 97.14, with 62/63 challenges solved. The exact public commit/configuration behind that run was not established.
- Cairn's inspected result validator accepts nonempty model descriptions; it does not independently verify their truth. Its inspected conclude adapters retain tool access despite summarize-only prompting.
- Cairn source reviewed: [`8e7e0ea67552383851dfcabfba0c4e9c8d007878`](https://github.com/oritera/Cairn/tree/8e7e0ea67552383851dfcabfba0c4e9c8d007878).
- Existing Apex state, evidence, and interrupted-finalization tests passed: 18 tests across three files. These establish the current baseline, not coverage of the proposed crash and provenance checks.
- Next implementation work should start with focused regression tests. No issue, code fix, or deployment was created by this review.
