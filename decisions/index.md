# Product Decision Records

This folder captures the key "why" decisions behind Apex — product, architecture, and UX choices that are non-obvious or have meaningful trade-offs. Each record follows the PDR format: Context → Decision → Rationale → Alternatives considered → Consequences.

---

## What is Apex trying to do?

> Make continuous, automated pentesting as routine as running unit tests.

Apex serves three audiences:

- **Professional pentesters** who want repetitive work automated
- **Security engineers** continuously testing their own infrastructure
- **Developers shifting security left** who want a pentest as part of their CI pipeline.

---

## Decisions

| #                                                 | Decision                                                                     |
| ------------------------------------------------- | ---------------------------------------------------------------------------- |
| [PDR-001](./PDR-001-tui.md)                       | Terminal UI over web app or headless CLI                                     |
| [PDR-002](./PDR-002-pentest-vs-operator.md)       | Two interaction modes — `/pentest` (automated) and `/operator` (interactive) |
| [PDR-003](./PDR-003-specialized-agents.md)        | Specialized sub-agent architecture with swarm orchestration                  |
| [PDR-004](./PDR-004-pentest-methodology.md)       | Rigid 7-step methodology in `TargetedPentestAgent`                           |
| [PDR-005](./PDR-005-findings-registry.md)         | Shared findings registry                                                     |
| [PDR-006](./PDR-006-public-api.md)                | Public API layer separate from the TUI                                       |
| [PDR-007](./PDR-007-multi-provider.md)            | Multi-provider AI model support                                              |
| [PDR-008](./PDR-008-provider-attempt-envelope.md) | Inference telemetry is a physical-attempt contract, not a billing ledger     |

---

## Adding a new decision

Copy this template into a new file named `PDR-NNN-short-description.md` and add a row to the table above.

```markdown
# PDR-NNN: Title

## Context

What situation or problem prompted this decision?

## Decision

What did we decide?

## Rationale

Why? What makes this the right call given the context?

## Alternatives considered

- **Option A** — rejected because...
- **Option B** — rejected because...

## Consequences

- ✅ Upside
- ⚠️ Trade-off or risk
```
