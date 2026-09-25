# PDR-010: Durable engagement lead with verified objective workers

## Context

The endpoint swarm gave each target a fresh orchestrator. That duplicated planning, fragmented threat-model context, and made cross-service exploit chains difficult to preserve. Fast Strike agents performed well on bounded exploitation objectives, but benchmark completion is not the same as production pentest completeness.

Production pentests must both discover and validate vulnerabilities across a complete attack surface. They also need a final attempt to compose confirmed primitives into crown-jewel impact without weakening finding validation or existing API contracts.

## Decision

Add an opt-in scan-level engagement lead that owns the complete discovered surface for the lifetime of a scan.

The lead can test directly and delegate focused work after a restricted planning pass. In grouped mode, the lead model first reads the complete paged attack surface and read-only product context, including business logic and threat models, then creates semantic missions; application code does not infer route families. Planning tools cannot execute tests or launch workers. The host validates and seals coverage before its bounded scheduler admits any mission. Each mission declares canonical security requirements, the exact endpoint/objective associations each requirement represents, supporting targets, rationale, context references, and prerequisites. Consolidation is allowed only after the planner has completely read the affected target context and determined that threat boundary, authentication state, expected behavior, and evidence requirements are equivalent. Workers have stable IDs, persisted conversations, directed `MESSAGE` and `FINAL_ANSWER` mailbox records, and an explicit follow-up operation. Independent assignments may run concurrently; stateful chains resume the same worker.

The lead, planner, workers, and finding judge retain code mode. Read-only target context is a host-governed nested capability scoped to the target IDs assigned to that agent. Context documents are immutable within a run, paged, redacted, versioned, and treated as untrusted data. The finding judge must read the complete scoped context before deciding whether reported behavior is a vulnerability, expected behavior, or informational; missing context remains an explicit verification limitation.

Fast Strike is a bounded objective executor. It returns `impact-proven`, `exhausted`, or `blocked`, and an impact claim must cite a successful observation from its own trace scope. Production defaults to one lane; competitive lanes are explicit benchmark configuration.

Engagement completion is deterministic:

- every objective attached to every in-scope target is terminal;
- grouped missions preserve related flows in one worker, and one canonical requirement result atomically settles all of its reviewed source associations; the source ledger remains available for audit and deterministic completion;
- failed or omitted cells retry once as singletons, then require lead resolution;
- service baselines derive from their terminal target coverage;
- candidate capabilities and confirmed capabilities with supported next steps are resolved;
- chain-and-explore reaches a terminal disposition.

The coverage ledger remains external to the lead's model context. The production progress contract is mission-centric: frontends render planning state and mission progress, while endpoint/objective associations remain backend audit and completion detail. Assignment,
execution, tested, blocked, and untested state remain distinct, so blocked work
never appears as tested coverage. Coordination
tools return compact pages, mutation acknowledgements, and state versions rather
than embedding the complete checkpoint after every update. Automatic exhausted
results stay in the ledger; only impact, blocking, and needs-lead signals enter
the lead mailbox.

Impact proofs reference accepted findings, capabilities, artifacts, or observations. They do not bypass `document_vulnerability` or the finding judge.

The host may independently select the lead and worker models. Unset selections inherit the existing pentest model, and resolved selections are persisted in the engagement checkpoint so resume does not silently change models.

The legacy endpoint swarm remains the default until the Console feature flags enable the engagement lead and grouped coverage.

## Rationale

A single owner preserves the causal history needed to recognize attack paths across services. Code mode keeps the lead capable of judgment-heavy testing while leaving lifecycle and evidence contracts first-class, and focused workers provide independent context windows without turning the lead into a passive manager. Deterministic source coverage prevents a model from ending the scan because one canonical requirement succeeded or a summary sounds complete.

Separating the objective executor from the engagement owner lets benchmark improvements transfer to production without importing benchmark-specific prompts or completion semantics.

## Alternatives considered

- **Continue one orchestrator per endpoint** — rejected because cross-service context and exploit primitives remain fragmented.
- **Manager-only lead** — rejected because it spends context translating every observation and cannot directly validate important hypotheses.
- **Fast Strike as the whole pentest** — rejected because proving one objective does not establish attack-surface or net-new vulnerability coverage.
- **Global Cartesian coverage** — rejected because copying every objective onto unrelated endpoints creates low-value work. Exhaustive coverage applies only to each target's declared objectives.

## Consequences

- ✅ One durable owner can discover, validate, and compose multi-service attack paths.
- ✅ Fast Strike results have a small production contract and trace-backed impact claims.
- ✅ Coverage and completion survive model context compaction and process resume.
- ✅ Related endpoint checks share bounded workers instead of paying for one session per endpoint.
- ✅ Equivalent endpoint/objective associations collapse into reviewed canonical requirements without losing source-level auditability.
- ✅ Workers and the finding judge ground decisions in scoped, versioned product context without receiving write access to it.
- ✅ Frontends can track bounded mission progress instead of rendering thousands of implementation-level objectives.
- ✅ Existing pentest APIs and the legacy path remain available during rollout.
- ⚠️ The lead has a larger context and requires careful compaction and budget monitoring.
- ⚠️ Worker concurrency must respect target state, browser isolation, and mutation safety.
