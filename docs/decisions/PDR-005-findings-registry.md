# PDR-005: Shared findings registry

## Context

In `/pentest` mode, many `TargetedPentestAgents` run in parallel across different targets and objectives. Each agent discovers and documents vulnerabilities independently. We need to decide how findings are collected — each agent returns its own result set at the end, or all agents write to a shared, centralised registry as they go.

## Decision

All agents write findings to a shared registry in `src/core/findings/` in real time. The registry is the single authoritative record for the engagement and is the source used by the report generator.

## Rationale

**Deduplication.** Multiple agents sweeping overlapping parts of an attack surface will inevitably discover the same vulnerabilities. Without a central registry, the final report would contain duplicate findings with varying levels of evidence. The registry deduplicates at write time, preserving only the strongest evidence for each unique finding.

**Live TUI updates.** The pentest dashboard displays findings as they are reported, not as a batch at the end. This is only possible if findings flow through a shared, observable store that the TUI can subscribe to. Agent-local result sets would require the TUI to poll every running agent independently.

**Single source of truth for reporting.** Report generation reads from one place rather than merging N agent outputs with potentially different schemas, confidence levels, and evidence formats. This simplifies the report generator and makes output consistent.

## Alternatives considered

- **Each agent returns a result set at the end** — rejected. No real-time visibility, deduplication requires a merge step with complex conflict resolution, and agents finishing at different times means the report can't be generated until the last agent finishes.
- **Agent-to-agent communication** — rejected. Overly complex; agents would need awareness of each other and a coordination protocol, which is hard to reason about and debug.

## Consequences

- ✅ Real-time finding visibility in the TUI as agents report
- ✅ Automatic deduplication across parallel agents
- ✅ Report generation reads from a single, canonical store
- ⚠️ Shared mutable state requires careful concurrency handling (registry writes must be safe from parallel agents)
- ⚠️ Registry becomes a critical dependency — a bug there affects all agents and all output
