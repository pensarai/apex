# PDR-010: Durable engagement lead with verified objective workers

## Context

The endpoint swarm gave each target a fresh orchestrator. That duplicated planning, fragmented threat-model context, and made cross-service exploit chains difficult to preserve. Fast Strike agents performed well on bounded exploitation objectives, but benchmark completion is not the same as production pentest completeness.

Production pentests must both discover and validate vulnerabilities across a complete attack surface. They also need a final attempt to compose confirmed primitives into crown-jewel impact without weakening finding validation or existing API contracts.

## Decision

Add an opt-in scan-level engagement lead that owns the complete discovered surface for the lifetime of a scan.

The lead can test directly and delegate focused work. Workers have stable IDs, persisted conversations, directed `MESSAGE` and `FINAL_ANSWER` mailbox records, and an explicit follow-up operation. Independent assignments may run concurrently; stateful chains resume the same worker.

Fast Strike is a bounded objective executor. It returns `impact-proven`, `exhausted`, or `blocked`, and an impact claim must cite a successful observation from its own trace scope. Production defaults to one lane; competitive lanes are explicit benchmark configuration.

Engagement completion is deterministic:

- every supplied objective is terminal on at least one relevant service;
- every in-scope service receives baseline exploration;
- candidate capabilities and confirmed capabilities with supported next steps are resolved;
- chain-and-explore reaches a terminal disposition.

Impact proofs reference accepted findings, capabilities, artifacts, or observations. They do not bypass `document_vulnerability` or the finding judge.

The legacy endpoint swarm remains the default until the Console feature flag enables the engagement lead.

## Rationale

A single owner preserves the causal history needed to recognize attack paths across services. Direct tools keep the lead capable of judgment-heavy testing, while focused workers provide independent context windows without turning the lead into a passive manager. Deterministic coverage prevents a model from ending the scan because one objective succeeded or a summary sounds complete.

Separating the objective executor from the engagement owner lets benchmark improvements transfer to production without importing benchmark-specific prompts or completion semantics.

## Alternatives considered

- **Continue one orchestrator per endpoint** — rejected because cross-service context and exploit primitives remain fragmented.
- **Manager-only lead** — rejected because it spends context translating every observation and cannot directly validate important hypotheses.
- **Fast Strike as the whole pentest** — rejected because proving one objective does not establish attack-surface or net-new vulnerability coverage.
- **Per-endpoint Cartesian coverage** — rejected because it creates low-value work; service baselines plus relevant-service objective execution capture the intended contract.

## Consequences

- ✅ One durable owner can discover, validate, and compose multi-service attack paths.
- ✅ Fast Strike results have a small production contract and trace-backed impact claims.
- ✅ Coverage and completion survive model context compaction and process resume.
- ✅ Existing pentest APIs and the legacy path remain available during rollout.
- ⚠️ The lead has a larger context and requires careful compaction and budget monitoring.
- ⚠️ Worker concurrency must respect target state, browser isolation, and mutation safety.
