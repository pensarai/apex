# PDR-010: Durable engagement lead with verified objective workers

## Context

The endpoint swarm gave each target a fresh orchestrator. That duplicated planning, fragmented threat-model context, and made cross-service exploit chains difficult to preserve. Fast Strike agents performed well on bounded exploitation objectives, but benchmark completion is not the same as production pentest completeness.

Production pentests must both discover and validate vulnerabilities across a complete attack surface. They also need a final attempt to compose confirmed primitives into crown-jewel impact without weakening finding validation or existing API contracts.

## Decision

Add an opt-in scan-level engagement lead that owns the complete discovered surface for the lifetime of a scan.

The lead can test directly and delegate focused work after a restricted planning pass. In grouped mode, the lead model first reads the complete paged attack surface and read-only product context, including business logic and threat models, then creates semantic missions; application code does not infer route families. Planning tools cannot execute tests or launch workers. The host validates and seals coverage before its bounded scheduler admits any mission. Each mission declares canonical security requirements, the exact endpoint/objective associations each requirement represents, supporting targets, rationale, context references, and prerequisites. Consolidation is allowed only after the planner has completely read the affected target context and determined that threat boundary, authentication state, expected behavior, and evidence requirements are equivalent. Workers have stable IDs, persisted conversations, directed `MESSAGE` and `FINAL_ANSWER` mailbox records, and an explicit follow-up operation. Independent assignments may run concurrently; stateful chains resume the same worker.

The lead, planner, workers, and finding judge retain code mode. Read-only target context is a host-governed nested capability scoped to the target IDs assigned to that agent. Context documents are immutable within a run, paged, redacted, versioned, and treated as untrusted data. The finding judge must read the complete scoped context before deciding whether reported behavior is a vulnerability, expected behavior, or informational; missing context remains an explicit verification limitation.

Planning working memory is a durable session artifact rather than planner conversation history. The host writes an immutable target/objective manifest and a separate editable mission-plan JSON file. In code mode the planner receives scoped versions of the existing filesystem capabilities: it may read those two files and replace only the plan file, while testing and arbitrary filesystem capabilities remain unavailable. The response boundary imports, validates, and seals a ready artifact atomically. The lead can read the sealed artifact directly, and workers may consult it for dependency or cross-mission context without replaying the planner transcript.

Planning is two-stage: the planner first canonicalizes requirements, then assigns requirement IDs to bounded missions. Before planning, the host seals evidence-backed deployment facts as available, unavailable, or unknown. Proven unavailable prerequisites terminally block their source associations without deleting them; unknown prerequisites remain runnable. Every singleton requirement records why it cannot be merged, preventing singleton output from bypassing complete context review.

The lead owns an explicit actor registry. Operator-provided credentials become safe credential references with role, target, service, and provenance metadata; secrets never enter engagement state. Workers receive only the references assigned to their mission and use actor-scoped browser/runtime state. Authorized prior-session memory remains readable, but a rediscovered identity does not silently become an authoritative actor without explicit registration and provenance.

Lead/worker coordination is event-driven. A replay-safe activity cursor wakes the lead on progress, handoff, escalation, failure, or completion. Code mode remains available throughout the workflow, but code-mode timers and polling loops are not a worker-monitoring mechanism.

Fast Strike is a bounded objective executor. It returns `impact-proven`, `exhausted`, or `blocked`, and an impact claim must cite a successful observation from its own trace scope. Production defaults to one lane; competitive lanes are explicit benchmark configuration.

Code-mode results expose the stable nested tool-call IDs that produced their observations rather than requiring workers to infer them from the outer code-cell ID. The host journals observation provenance and includes it in engagement checkpoints so resumed workers can cite earlier successful observations. Every supplied evidence reference is validated against the assigned worker scope before it is persisted, and grouped result batches validate in full before any coverage cell is mutated.

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

Attack chains are first-class engagement records rather than synthetic vulnerability findings. Proven, exhausted, and blocked chains carry their own narrative, impact, evidence, ordered steps, and terminal disposition, while linking to stable finding, capability, impact-proof, objective, service, and target IDs. This preserves vulnerability counts and judge authority while giving frontends a durable relation graph. The reporting phase deterministically compiles findings, chains, mission progress, coverage, and the final chain-and-explore disposition into JSON and a concise Markdown overview before the detailed finding write-ups.

Chain completion requires a dedicated attacker-path chain for every canonical finding, including single-finding paths, and representation of every recorded impact proof. Composite chains are additive and cannot replace those dedicated paths. Prior-session documentation is testing context rather than a reason to suppress a currently validated path; the finding judge and canonical consolidation remain authoritative for validity and duplication.

Accepted findings are canonically consolidated before chain exploration. Duplicate records remain available for audit but resolve to one stable finding ID; related-but-distinct findings may share a root-cause group without changing vulnerability counts. New chains require ordered evidence-bearing steps with referential integrity. Legacy prose-only chains remain readable and are marked incomplete rather than receiving invented evidence.

The host may independently select the lead, worker, and finding-judge models. Unset selections inherit the existing pentest model, and resolved selections are persisted in the engagement checkpoint so resume does not silently change models. Engagement runs also persist role/model usage, code-cell activity, wall time, and provider-reported cost provenance; unavailable cost is not represented as zero.

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
