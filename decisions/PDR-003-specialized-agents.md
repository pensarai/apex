# PDR-003: Specialized sub-agent architecture with swarm orchestration

## Context

A full penetration test spans multiple distinct phases — recon, authentication analysis, targeted exploitation, code analysis, reporting — each requiring different expertise, different tool sets, and different prompt strategies. We need to decide whether a single general-purpose agent runs the full engagement or whether specialized agents handle each phase independently.

Additionally, real engagements involve tens or hundreds of targets. Sequential execution would be impractically slow for continuous or CI-driven pentesting.

## Decision

We use a three-tier hierarchy:

1. **`OffensiveSecurityAgent`** — the base harness. Owns tools, approval gate, message persistence, context summarization, and subagent callbacks.
2. **Specialized agents** (`TargetedPentestAgent`, `AttackSurfaceAgent`, `AuthenticationAgent`, `CodeAgent`, etc.) — each has a tight, expert-level prompt scoped to a single mission.
3. **Orchestration tools** (`spawn_pentest_swarm`, `run_attack_surface`, `spawn_coding_agent`) — tools the base agent can call that spin up fleets of specialized agents with bounded concurrency.

Fast strike is a reusable objective executor within this hierarchy. A user can select it directly with a custom target, scope, and goal, or a pentest orchestrator can select `executionMode: "fast-strike"` for one concrete exploit-impact objective. Its terminal status (`impact-proven`, `exhausted`, or `blocked`) applies only to that assigned objective; it never marks the wider engagement complete.

## Rationale

**Context window fidelity and recall.** A single agent running a full engagement accumulates noise — recon output, failed attempts, intermediate artifacts — that degrades the quality of later reasoning. Specialized agents start every run with a clean, focused context. When targeting specific objectives or testing a specific hypothesis, a scoped agent has dramatically higher recall and precision than a general-purpose agent with thousands of tokens of unrelated history.

**Specialization quality.** An authentication agent that only thinks about auth flows (SSO, OAuth, session fixation, MFA bypass) can have a far tighter, more expert prompt than a jack-of-all-trades agent. The specialized prompt encodes domain knowledge that would be diluted in a general prompt.

**Parallelism and scale.** The swarm model lets N `TargetedPentestAgents` run simultaneously on different targets and objectives, matching how a real red team operates. Sequential execution across a large attack surface would make continuous pentesting impractical.

**Reusability and composability.** Specialized agents are exposed through the public API (`src/core/api/`) so they can be called independently — in the TUI, in CI pipelines, in Pensar Console, or embedded in third-party tools. The stub architecture means any agent can be reused or recombined without pulling in the full TUI.

## Alternatives considered

- **Single general-purpose agent** — this is exactly what powers `/operator` mode. It works well for interactive, human-steered sessions where the operator is directing the engagement. It doesn't scale to automated pipelines: context window accumulation degrades performance over a long engagement, and a single prompt cannot be simultaneously expert-level across recon, auth, exploitation, and code analysis.
- **Fixed pipeline (no orchestration tools)** — rejected. A hardcoded pipeline can't adapt when the orchestrator needs to spawn additional agents based on what it discovers at runtime.

## Consequences

- ✅ Each agent starts with focused context, maximizing recall on specific objectives
- ✅ Parallel swarm execution scales to large attack surfaces
- ✅ Specialized prompts encode domain expertise per phase
- ✅ Agent stubs are independently reusable via the public API and Pensar Console
- ⚠️ More moving parts: inter-agent communication, subagent lifecycle management, bounded concurrency logic
- ⚠️ Debugging a failure requires tracing across multiple agent sessions and message logs
