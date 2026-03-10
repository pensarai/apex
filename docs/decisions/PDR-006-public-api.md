# PDR-006: Public API layer separate from the TUI

## Context

The agent logic — attack surface mapping, targeted pentesting, authentication analysis — is currently invoked from within the TUI. As Apex grows, other consumers need access to the same agent capabilities: automated CI pipelines, third-party integrations, and Pensar Console (our cloud-hosted continuous pentesting product). We need to decide whether agent capabilities are bundled exclusively with the TUI or exposed through a clean, stable API surface.

## Decision

We maintain a public API layer at `src/core/api/` that exposes all agent capabilities independently of the TUI. The TUI is one consumer of this API, not the only one.

## Rationale

**Pensar Console and CI/CD.** Pensar Console is our cloud-hosted product that adds scheduling, org management, and CI/CD webhooks on top of the same agent primitives. It cannot depend on the TUI. The public API is the shared foundation that both the TUI and Console consume. It also enables direct CI integration: teams can trigger individual agents (e.g., run the attack surface agent on every new asset) from a deployment pipeline without launching the full TUI.

**SDK for builders.** Other tools and security platforms can embed individual Apex agents — auth agent, attack surface agent, pentest swarm — without pulling in the TUI. The agent stubs are designed to be independently instantiated and consumed.

**Testability.** The TUI is difficult to integration-test because it requires terminal rendering, keyboard input, and interactive flows. The API layer is straightforward to test programmatically, which is why integration tests in `src/tests/` and `src/core/api/` target the API directly.

## Alternatives considered

- **TUI as the only interface** — rejected. Would make Console impossible to build on the same codebase and would require duplicating agent logic. Also makes programmatic testing of agent behavior impractical.
- **Separate package for agent logic** — rejected at this stage. A single-package repo is simpler to maintain, and the API layer boundary within the package gives us the same separation without the overhead of multi-package publishing and versioning.

## Consequences

- ✅ Pensar Console and CI integrations can call individual agents without the TUI
- ✅ Agent stubs are independently reusable and composable
- ✅ Integration tests can cover agent behavior without terminal emulation
- ⚠️ API layer must remain stable — breaking changes affect both the TUI and Console
- ⚠️ Requires discipline to keep agent logic in `src/core/` and not leak TUI concerns into it
