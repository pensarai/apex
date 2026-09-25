# Engagement lead: grounding and mission progress plan

Date: 2026-09-13

Status: Apex backend implemented; Console consumer pending its frontend checkout.
Branch inspected: `codex/harness-engagement-lead`.

## Scope and outcomes

Give agents consistent, read-only access to the authorized target context through code mode; ground finding review in product expectations; support threat-model-reviewed consolidation of objectives into mission plans; and make missions the primary frontend progress unit.

This plan covers metadata access, evidence adjudication, reviewed planning artifacts, and progress reporting. It does not expand autonomous testing permissions, implement autonomous exploit chaining, or change automated test selection and dispatch. Mission-centric presentation alone will not reduce executed work; measure actual duplication separately before claiming savings.

Keep the existing finding judge, authorization boundaries, isolated runtime, and durable state. Build on [PDR-008](decisions/PDR-008-model-agnostic-code-runtime.md), [PDR-010](decisions/PDR-010-engagement-lead.md), and the stable public API in [PDR-006](decisions/PDR-006-public-api.md). The earlier [reliability gap plan](ENGAGEMENT-LEAD-GAP-PLAN.md) remains applicable.

## Verified starting points

- `EngagementSurfaceProvider` already exposes target details including `threatModel`, `businessLogic`, authentication requirements, and objectives. Reuse this interface rather than adding a second data service.
- Injected `extraTools` are currently promoted to top-level tools and excluded from the nested code-mode allowlist. Therefore adding a context tool to `extraTools` does not make it callable inside `exec`.
- Planning, the lead, and workers already forward protocol preferences in their principal paths. The finding judge does not explicitly receive that preference or the surface provider.
- The documenting tool validates `sourceTargetId`, but the explicit judge input does not carry that ID or the corresponding threat-model context.
- Identical trimmed objective text is deduplicated, but coverage remains per endpoint/objective pairing. Missions currently group these obligations without consolidating their semantics.
- The public API exposes checkpoints and summary metrics. The Console frontend implementation is not present in this checkout; do not invent its component paths.

## 1. Scoped read-only context capability

Primary integration points: [surface tools](src/core/workflows/engagementSurface.ts), [engagement API](src/core/api/engagementPentest.ts), [lead](src/core/workflows/engagementLead.ts), [worker context](src/core/workflows/engagementTools.ts), and [tool context](src/core/agents/offSecAgent/tools/types.ts).

- Reuse `search_engagement_surface` and `get_engagement_target`; keep IDs and bounded pagination rather than arbitrary URLs, file paths, SQL, or executable arguments.
- Bind reads to the host-authorized engagement snapshot and caller's allowed target IDs. Enforce access in host code, not descriptions or prompts. Do not expose workspace-wide metadata or credentials.
- Include context provenance: target ID, snapshot/version reference, product expectations, authentication model, threat-model content, and whether a statement is authoritative documentation or a generated hypothesis. Return explicit missing/unavailable states.
- Bound output size and paginate long content without silently truncating relevant context. Cache only against a versioned snapshot; surface stale context on resume rather than silently mixing versions.
- Persist references and read receipts, not live provider objects. Rehydrate the scoped provider on resume and verify it matches the saved snapshot.
- Treat returned documents as data. Instructions embedded in target descriptions must not change scope, tool permissions, or judge rules.

| Consumer                     | Context visibility                                                                           |
| ---------------------------- | -------------------------------------------------------------------------------------------- |
| Planning and engagement lead | Authorized engagement snapshot                                                               |
| Mission worker               | Assigned targets and explicitly declared supporting/context targets                          |
| Finding judge                | Validated source target and explicitly authorized related context needed to assess the claim |
| Other evidence reviewers     | Minimum referenced context for their review task                                             |

The provider is read-only. Access to context grants no additional permission to interact with the described target.

Acceptance: an allowed read succeeds through code mode; an unknown or unauthorized ID fails before data disclosure; pagination cannot escape scope; missing context is explicit; snapshot identity survives resume; no mutation capability becomes reachable through the read interface.

## 2. Code-mode availability across phases

Primary integration points: [tool presentation](src/core/agents/offSecAgent/offensiveSecurityAgent.ts), [code-mode tools](src/core/agents/offSecAgent/codeMode/tools.ts), [runtime profile](src/core/ai/modelRuntime.ts), and the finding-judge constructor/runtime inputs.

- Make presentation intent explicit for the new read capabilities so they can enter the governed nested bridge. Preserve the existing default for unrelated injected tools; do not globally move all `extraTools` into code mode.
- Keep canonical schemas, argument validation, scope guards, cancellation, and lifecycle events identical regardless of presentation.
- Forward the session's protocol preference through every nested reviewer and resumed session. Resolve provider-appropriate code transport using the existing resolver; do not hard-code model names or copy one provider's resolved native transport to another provider.
- Make the resolved protocol observable. An explicit compatibility override can remain supported, but a production session expecting code mode must not silently become direct-only in a child agent.
- Preserve first-class lifecycle contracts such as `response`, finding submission, checkpoints, and structured progress reporting. Code mode throughout does not mean forcing every lifecycle action inside `exec`.
- Verify role permissions independently of protocol: a planner's `exec` can call only its existing planning contracts and authorized reads. It must not gain shell, target-network, or worker-launch capabilities merely because code mode exists.

Acceptance: a mocked role matrix covers planner, lead, grouped worker, Fast Strike worker, finding judge, and resumed reviewer. Each can use its authorized context reads through the appropriate code profile, unavailable capabilities remain unavailable, and terminal response/cancellation behavior is unchanged.

## 3. Threat-model-grounded finding adjudication

Primary integration points: [documenting tool](src/core/agents/offSecAgent/tools/documentFinding.ts) and [finding judge](src/core/agents/specialized/findingJudge/index.ts), including its input types, agent, prompts, and tests.

- Pass the already-validated `sourceTargetId`, snapshot reference, scoped read capability, and protocol preference into the judge. Avoid guessing context from the engagement's root URL when the claim concerns a different target.
- Require a successful read of the applicable context, or an explicit unavailable-context disposition. Record the actual referenced version; a model claiming it read a document is not a read receipt.
- Ground the judgment in expected product behavior, the observed evidence, the claimed security expectation, and any unresolved assumptions. Keep context interpretation independent of the worker's narrative.
- Missing product expectations must not be invented. Generated threat models guide assessment but are neither authorization documents nor an exhaustive allowlist of valid findings. Intended functionality can still have unintended security consequences.
- Retain `expected-behavior` classification and fail-closed handling of unverified claims. Infrastructure failure, unavailable context, and substantive rejection must remain distinguishable in review records.
- Reconcile the stale document-finding test that expects acceptance after degraded verification with the current judge failure handler, which rejects unverified findings.
- Treat independent judge-model configuration as a separate follow-up, not a prerequisite for grounding or a reason to weaken acceptance rules.

Acceptance: fixtures distinguish intended public behavior from a documented policy violation; ambiguous or missing context remains unresolved; an omitted threat-model scenario is not automatically rejected; worker-supplied prose cannot override authoritative context; judge failure cannot persist an accepted vulnerability.

## 4. Reviewed objective consolidation into mission plans

Primary integration points: [planning](src/core/workflows/engagementPlanning.ts), [mission records](src/core/workflows/engagementMissions.ts), and [state](src/core/workflows/engagementState.ts).

- Amend PDR-010 before changing the meaning of coverage. Specify the distinction between a canonical review requirement, source objective/endpoint associations, a mission, and evidence of testing.
- Allow the lead to propose consolidation in planning/review: a shared description, all original objective IDs and target associations, rationale, relevant context references, and explicitly retained distinctions.
- Require the planning lead to read complete scoped target context before semantic consolidation. The host validates reference integrity and source accounting; text similarity or endpoint grouping alone cannot establish equivalent behavior or coverage.
- Preserve every source association in the audit view. Represent duplicate wording once in the reviewed plan without marking other endpoints tested by inheritance.
- Keep executed mission definitions immutable. Revisions are limited to unsealed plans and must not rewrite historical evidence or silently change an active contract.
- Do not relax completion by deleting source obligations. A canonical requirement result atomically settles its reviewed source associations, which remain in the coverage ledger.

Acceptance: a large synthetic manifest produces a reviewable consolidated representation with every source association accounted for. Different product expectations remain distinct. Unsealed changes cannot modify active records, and consolidation cannot manufacture tested coverage.

## 5. Mission-centric UI and frontend contract

Primary Apex integration points: [checkpoint metrics](src/core/workflows/engagementMetrics.ts), [public API](src/core/api/engagementPentest.ts), and [event identities](src/core/eventBus.ts). Identify the Console adapter/frontend repository before implementation there.

- Use one top-level row per logical mission and primary progress based on mission state. Remove endpoint/objective completion counters from the primary progress display; keep their provenance in an expandable audit view.
- Nest worker attempts and judge sessions under the mission. A new attempt or judge must not create another mission or inflate completion counts. Preserve stable mission, session, and parent identifiers across reconnects.
- Show planning separately until a plan is sealed. Display completed, running, waiting-for-review, blocked, and failed states distinctly where supported by the backend; add no frontend-only invented lifecycle state.
- Do not count blocked/failed work as successfully completed or imply that mission progress equals complete security assurance. Findings awaiting a judge remain pending review.
- Derive progress from versioned backend checkpoints, not chat text, tool-call volume, or the number of sessions. Reconnects and out-of-order updates must not regress newer state.
- Surface plan revisions explicitly so changed denominators do not look like lost progress. Do not create a speculative percentage-complete estimate from elapsed time or objective counts.
- Keep backend coverage and acceptance gates intact. This is mission-centric presentation, not removal of auditability.

Acceptance: multiple attempts and nested judges still render one mission; blocked work is visibly incomplete; reconnect restores the same state; duplicate/out-of-order updates are harmless; plan revisions are visible; legacy checkpoints have an explicit compatibility presentation.

## Delivery order and validation

1. Confirm the Console ownership and wire its consumer to the exported mission projection.
2. Land a focused tool-presentation refactor with regression tests and no new capabilities.
3. Add scoped read-only context access and judge/protocol plumbing with fixture-only tests.
4. Add reviewed consolidation metadata, checkpoint compatibility, and atomic canonical-requirement reporting while retaining every source association.
5. Ship the mission projection and frontend as a versioned consumer contract.

Use synthetic manifests, mock providers, and recorded/sanitized evidence fixtures; no live target tests are needed for this work. Add checks to existing surface, code-mode, judge, planning, state, and metrics suites. Run the full `bun run test`, type checks, formatting/lint checks, and build for implementation changes. Exclude nested `.worktrees` when running focused tests so unrelated checkouts do not contaminate results.

Measure context-read failures, unresolved-context judgments, intended-behavior classification accuracy, mission/session count differences, and cost by role. Report measured work separately from theoretical avoided per-cell workers. The first production comparison needs a representative completed engagement trace; this plan does not promise a particular reduction in testing cost.

Implemented in this checkout: the code-mode presentation seam, scoped and versioned context reads, context-grounded judge flow, canonical mission requirements with source-association accounting, atomic requirement settlement, mission progress projection, public API exports, and the PDR-010 amendment. The Console UI is not present in this checkout, so rendering the exported projection remains a consumer-repository task. No deployment or issue creation was performed.
