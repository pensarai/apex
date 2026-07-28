# PDR-008: Model-agnostic code-oriented agent runtime

## Context

Offensive-security agents frequently need to loop, branch, build small scanners, and compose several actions. Exposing the entire Apex registry as dozens of independent function schemas makes that work verbose and provider-sensitive. In Evalgate, GPT-5.6 Sol performed materially better in its native Codex harness than behind Apex's broad schema surface. At the same time, Apex must continue to support Anthropic through Bedrock, open models through OpenRouter, and the stable tool lifecycle consumed by Console.

The Console contract is semantic, not a requirement that every capability be a top-level model schema. `response`, `document_vulnerability`, and `checkpoint_state` are exceptions: their schemas, stop behavior, and UI affordances are important enough to remain first-class.

## Decision

Apex separates canonical capabilities from their model-facing presentation.

Fast-strike resolves a provider profile by default:

- GPT-5.6 Sol on OpenAI uses the provider's native freeform custom `exec` tool.
- Claude Opus 4.8 on Bedrock and GLM-5.2 on OpenRouter use a schema-based `exec({ code })` tool.
- Unknown models retain the direct tool registry until deliberately profiled.
- Operators can override the protocol with `toolProtocol`.

Code profiles expose `exec`, `wait`, `response`, `document_vulnerability`, and `checkpoint_state`. The isolated JavaScript runtime can invoke a small allowlist of canonical shell and browser capabilities. Nested invocations pass through the original schema validation, approval wrappers, implementations, and AgentEventBus lifecycle. Console therefore continues to observe canonical tool names and results regardless of the model protocol.

The JavaScript runtime uses QuickJS with a memory ceiling, deadline interrupt, abort propagation, bounded output, and no direct filesystem, process, or network globals. It exposes only explicit host bridges. Independent nested calls can be composed with `Promise.all`; sandbox Camoufox actions are serialized per sandbox because they share one persistent Firefox profile.

Code mode also exposes bounded concurrency helpers and reports per-cell execution metrics. The capability bridge conservatively detects repeated one-call cells, sequential batches, and identical calls that repeatedly return the same result. It returns advisory process guidance with the completed cell rather than blocking execution. This improves long-horizon discipline without changing capability authority or preventing intentional race and fuzzing programs.

Non-fast-strike modes remain on direct tools by default. This limits the initial behavioral change to the benchmarked workflow while allowing explicit experiments elsewhere.

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
- ✅ Parallel shell/request orchestration without concurrent Camoufox profile corruption
- ✅ Observable code-mode efficiency and advisory stagnation feedback without benchmark-specific knowledge
- ✅ Direct host filesystem and network access are absent from guest JavaScript
- ⚠️ QuickJS is a new runtime dependency and requires lifecycle and memory-leak tests
- ⚠️ Provider profiles require benchmark calibration as model behavior changes
- ⚠️ `execute_command` still inherits Apex's existing command-string scope limitation for destinations embedded in scripts. Production sandboxes should enforce egress at the process/network boundary; code mode does not broaden command authority, but it does not solve that infrastructure limitation
- ⚠️ Session-scoped OAST routing remains infrastructure work. When added, it should expose a callback URL/port to the sandbox rather than another model-facing tool
