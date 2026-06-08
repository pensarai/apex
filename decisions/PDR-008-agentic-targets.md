# PDR-008: Agentic targets as a first-class scan type

## Context

Apex was built to pentest web applications: a target is a URL, the attack surface is HTTP endpoints, and a finding is proven by an executable POC that exits 0. A growing class of customers ships AI agents / LLM apps (chat assistants, tool-using agents, multi-agent workforces) whose most important vulnerabilities — prompt injection (direct and indirect), tool/connected-action abuse, data exfiltration, and agent-to-agent handoff abuse — are not HTTP bugs and are not proven by a shell script. We validated this class with standalone prototype harnesses that share one shape: a corpus of adversarial cases delivered through a target adapter, with success detected by out-of-band **canary callbacks** plus transcript signals. We need to bring that capability into the product so an agent can be scanned through Apex like any other target.

## Decision

Add **agentic** as a first-class session type alongside `web-app`. A new in-core module (`src/core/agentic/`) generalizes the harness pattern — case corpus, canary oracle, and a **generic-first** target-adapter layer (an `openai-compatible` chat adapter and a configurable `http-json` adapter, with a thin `TargetAdapter` interface for future vendor SDKs). A dedicated workflow (`runAgenticPentestWorkflow`) scopes the corpus to the target's capabilities, runs each case through the adapter, scores it deterministically with the canary oracle, and registers exploited cases as findings in the existing `FindingsRegistry`. It is exposed via `src/core/api/` (`runAgenticPentestAgent`), a `pensar agentic-pentest` CLI command, and a `/agentic` TUI command + operator skill/tool.

## Rationale

**Generic-first adapter.** Most agent products expose an HTTP endpoint; an OpenAI-compatible adapter plus a field-mapping `http-json` adapter cover the long tail without per-vendor code. A `TargetAdapter` seam keeps vendor SDKs as additive follow-ups.

**Canary-proof findings, not POC scripts.** Agent exploits are proven by an out-of-band callback (the agent hit our collector) or a transcript signal (it echoed a planted secret), not by a runnable script. The deterministic oracle already produces a verdict, so the workflow builds a `Finding` and registers it directly — the canary transcript is the proof artifact (`pocPath` points at it) rather than an executable POC. This reuses dedup, root-cause grouping, reporting, and the findings UI unchanged.

**Reuse the existing pipeline.** New vuln classes (`prompt-injection`, `indirect-prompt-injection`, `tool-abuse`, `data-exfiltration`, `agent-handoff`) plug into `VULN_CLASS_PATTERNS`; the report `mode` enum gains `agentic`; evidence types gain `agent-transcript` and `canary-callback`. No parallel reporting/UI stack.

## Alternatives considered

- **Bend the web-app pipeline** (make `TargetedPentestAgent` test agents) — rejected. Its tools, methodology, and POC gate assume HTTP targets; forcing canary-based agent exploits through `document_vulnerability` (which requires an executable POC that exits 0) would mean a fake POC and a misaligned judge.
- **Per-vendor adapters from day one** — rejected as the starting point. Higher cost, narrower reach; deferred behind the `TargetAdapter` interface.
- **Keep the standalone harnesses** — rejected as the end state. They are throwaway per-target prototypes; the rule-of-three was the signal to generalize into core.

## Consequences

- ✅ Agents are scannable end to end (CLI, API, TUI) through the same session/findings/report flow.
- ✅ One corpus + oracle serves many targets; new adapters are additive.
- ✅ Findings land in the existing registry/report with agent-specific classes.
- ⚠️ Canary callbacks require the collector to be publicly reachable. MVP uses a configurable `canary.publicUrl` (tunnel) with a local `node:http` collector; a hosted canary service is a follow-up. Token-echo / transcript signals work without a tunnel.
- ⚠️ CVSS 4.0 maps imperfectly to agentic classes. Agent-driven findings are judged (`FindingJudge` canary mode) and CVSS-scored with agentic-class guidance; a proof-aware guardrail clamps `UI:N`→`UI:P` when only a token-echo (not an outbound canary callback) was observed, so render/click-conditional exfil isn't over-scored as zero-interaction. The deterministic path still takes severity from the case definition.
- ⚠️ A new session type and adapter layer are new critical surface to maintain.
