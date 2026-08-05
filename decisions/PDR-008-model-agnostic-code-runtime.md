# PDR-008: Model-agnostic code-oriented agent runtime

## Context

Offensive-security agents frequently need to loop, branch, build small scanners, and compose several actions. Exposing the entire Apex registry as dozens of independent function schemas makes that work verbose and provider-sensitive. In Evalgate, GPT-5.6 Sol performed materially better in its native Codex harness than behind Apex's broad schema surface. At the same time, Apex must continue to support Anthropic through Bedrock, open models through OpenRouter, and the stable tool lifecycle consumed by Console.

The Console contract is semantic, not a requirement that every capability be a top-level model schema. `response`, `document_vulnerability`, and `checkpoint_state` are exceptions: their schemas, stop behavior, and UI affordances are important enough to remain first-class.

## Decision

Apex separates canonical capabilities from their model-facing presentation.

Every `OffensiveSecurityAgent` resolves a provider-capability profile:

- OpenAI Responses uses the provider's native freeform custom `exec` tool.
- Providers exposing ordinary function tools use `exec({ code })`.
- Operators and development harnesses can override the protocol with
  `toolProtocol` or `APEX_CODE_MODE`.
- Model names never select the architecture.

Code profiles expose `exec`, `wait`, and the active workflow's lifecycle,
persistence, interaction, and evidence contracts. This includes responses,
findings, checkpoints, recon records, questions, errors, workflow submissions,
and browser screenshots. All other active capabilities are invoked inside the
isolated runtime. Nested invocations pass through the original validation,
approval wrappers, policy guards, implementations, and AgentEventBus lifecycle.

The JavaScript runtime uses QuickJS with a memory ceiling, deadline interrupt, abort propagation, bounded output, and no direct filesystem, process, or network globals. It exposes only explicit host bridges. The persistent shell, browser, and Console contract capabilities are stateful single-lane resources; overlapping calls fail fast with actionable guidance. Models implement request-level concurrency inside one reusable sandbox program rather than queuing parallel calls against those resources.

Code mode also exposes bounded concurrency helpers for capabilities that are explicitly safe to invoke concurrently and reports per-cell execution metrics. The capability bridge conservatively detects repeated one-call cells, sequential batches, and identical calls that repeatedly return the same result. It returns advisory process guidance with the completed cell. Code-mode shell calls default to a 120-second timeout, and explicit command timeouts include queue wait, so one blocked command cannot monopolize the shell or silently multiply the deadline of every queued caller.

Rollout is controlled independently from model identity through the developer
flag and protocol override; the runtime itself applies to every specialized
offensive-security role.

## Rationale

**Model-native ergonomics without provider lock-in.** OpenAI models can use their optimized freeform interface while schema-oriented providers receive the same semantics through a portable wrapper.

**Scripts become first-class orchestration.** Models can create bounded request harnesses and protocol logic in JavaScript instead of spending turns selecting individual tools. The model owns control flow; Apex owns execution authority.

**Stable product contract.** Capability invocation and AgentEventBus events stay canonical. Console does not need provider-specific translators, and finding/checkpoint/response tools retain their exact schemas.

**Fail-closed capability boundary.** Guest JavaScript cannot import host modules or access the network directly. Naming an unavailable capability fails before execution, and a submitted response makes further nested calls terminal.

## Alternatives considered

- **Use OpenAI's native code-mode protocol for every provider** — rejected. Bedrock and OpenRouter do not expose that provider-defined tool format.
- **Keep all tools top-level alongside exec** — rejected. It preserves the schema overload and lets the model bypass the code-oriented interface unpredictably.
- **Remove response, finding, and checkpoint tools in favor of prose or files** — rejected. They are durable Console contracts with validation and lifecycle semantics.
- **Run model-authored JavaScript in Bun or Node** — rejected. A same-process runtime would expose host APIs and make containment depend on fragile source inspection.

## Consequences

- ✅ A compact interface for long-horizon offensive work across OpenAI, Bedrock, and OpenRouter
- ✅ Canonical approval, event, finding, checkpoint, and response behavior is preserved
- ✅ Script-owned request concurrency without persistent-shell queues or concurrent Camoufox profile corruption
- ✅ Observable code-mode efficiency and advisory stagnation feedback without benchmark-specific knowledge
- ✅ Direct host filesystem and network access are absent from guest JavaScript
- ⚠️ QuickJS is a new runtime dependency and requires lifecycle and memory-leak tests
- ⚠️ Provider transports require compatibility tests as provider behavior changes
- ⚠️ Source classification is defense in depth; strict production sessions still require an externally-attested process-tree egress boundary
