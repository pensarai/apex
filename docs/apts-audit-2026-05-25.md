# OWASP APTS Security Audit — Apex

**Date:** 2026-05-25  
**Auditor:** Cursor Cloud Agent  
**Standard:** OWASP Autonomous Penetration Testing Standard (APTS) v0.1.0  
**Source:** https://github.com/OWASP/APTS  
**Scope:** Tier 1 (Foundation) requirements — all MUST-classified, Tier 1 requirements across all 8 domains

---

## Audit Table — Tier 1 MUST Requirements

> **Legend:** ✅ meets | ⚠️ partial | ❌ gap | N/A not applicable  
> **Evidence format:** `file:line` relative to repo root.

### 1. Scope Enforcement (SE)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-SE-001 | "The autonomous system MUST ingest Rules of Engagement documents in a machine-parseable format and validate all scope specifications before test initialization." | `src/core/session/index.ts:65-69` — `scopeConstraints` schema (allowedHosts, allowedPorts, strictScope). `src/tui/components/session/web-wizard.tsx` — TUI config wizard. | ⚠️ partial | Session config captures hosts/ports but no formal RoE document validation, no signature verification, no field-completeness checks. Missing: authorization proof, escalation procedures, temporal boundaries. |
| APTS-SE-002 | "The system MUST validate all IP ranges in scope specifications using CIDR notation parsing." | No CIDR parsing found. `src/core/agents/offSecAgent/tools/scopeGuard.ts:60-83` — host-based (eTLD+1) only. | ❌ gap | No IP range validation, no RFC 1918 awareness, no metadata endpoint blocking. |
| APTS-SE-003 | "The system MUST validate all domain specifications in scope and MUST implement clear policies for wildcard domain handling." | `scopeGuard.ts:60-83` — extracts eTLD+1 from targets and expands allowed hosts. | ⚠️ partial | Implicit wildcard via eTLD+1 expansion but no explicit wildcard policy, no third-party infrastructure exclusion. |
| APTS-SE-004 | "The system MUST enforce temporal boundaries (start time, end time) with sufficient precision." | Not implemented. | ❌ gap | No temporal boundary support in session config or enforcement. |
| APTS-SE-005 | "The system MUST support asset criticality classifications." | Not implemented. | ❌ gap | No asset criticality classification. |
| APTS-SE-006 | "The system MUST perform scope validation immediately before every network action." | `scopeGuard.ts` — `assertUrlInScope` called in `httpRequest.ts:133`. `executeCommand.ts` imports scope guard. | ⚠️ partial | HTTP URLs validated; command-line scope enforcement exists. But no DNS resolution re-validation, no redirect chain validation (followRedirects bypasses scope on intermediate hops). |
| APTS-SE-008 | "The system MUST continuously monitor and enforce temporal scope boundaries." | Not implemented. | ❌ gap | No temporal monitoring. |
| APTS-SE-009 | "The system MUST maintain a hard deny list of assets." | Not implemented. | ❌ gap | No deny list mechanism. |
| APTS-SE-015 | "The system MUST maintain complete audit logs of all scope enforcement decisions." | `scopeGuard.ts` — throws `ScopeViolationError` on failure; `httpRequest.ts` returns error to agent. `trace.jsonl` records tool calls. | ⚠️ partial | Scope violations logged as tool errors in trace but no dedicated scope decision audit log. |

### 2. Safety Controls (SC)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-SC-001 | "MUST implement a multi-tier impact classification system that categorizes every pentest action before execution." | `src/core/findings/cvssScorer/` — CVSS 4.0 scoring for findings. `src/core/agents/specialized/attackSurface/blackboxRiskScoring.ts:55-77` — heuristic risk scores. | ⚠️ partial | Findings are scored after discovery, not actions before execution. No per-action CIA scoring or pre-execution classification. |
| APTS-SC-004 | "MUST implement hierarchical rate limiting and payload constraints for all active pentest operations." | `src/core/services/rateLimiter/index.ts` — token-bucket rate limiter. `src/core/session/index.ts:459-461` — instantiated per session. `src/core/agents/offSecAgent/tools/httpRequest.ts:135` — **now wired** (this PR). | ⚠️ partial | **This PR fixes the core gap** — rate limiter was dead code, now enforced on http_request. Still missing: per-host limits (currently global), subnet/engagement-wide cascading, payload size constraints. |
| APTS-SC-009 | "The platform MUST provide multiple independent kill switch mechanisms enabling immediate halt." | `src/tui/components/operator-dashboard/logic.ts:181-190` — two-stage Ctrl+C. `AbortController` threaded through agents. `approvalGate.denyAll()`. | ⚠️ partial | Local abort mechanism works. Missing: remote halt, automatic failsafe on control-plane loss, Phase 1/2 timing guarantees, process tree enumeration. |
| APTS-SC-010 | "The platform MUST continuously monitor the health and responsiveness of target systems." | Not implemented. | ❌ gap | No target health monitoring or automatic halt on degradation. |
| APTS-SC-015 | "MUST perform thorough integrity validation after engagement completes." | Not implemented. | ❌ gap | No post-test integrity validation. |
| APTS-SC-020 | "The platform MUST define the agent's permitted tool and action space as an explicit allowlist, and the allowlist MUST be enforced by a component external to the model." | `src/core/agents/offSecAgent/tools/index.ts:317-386` — `ALL_TOOL_NAMES`. `offensiveSecurityAgent.ts:301-312` — `activeTools` passed to AI SDK. Plan mode intersection at lines 308-312. | ⚠️ partial | Tool allowlist is external to model and enforced by AI SDK. But: toolset presets (recon-only, minimal) in `src/core/toolset/` are not wired to agent activeTools at runtime. No version control or change-management on the allowlist. |

### 3. Human Oversight (HO)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-HO-001 | "MUST implement mandatory approval gates that prevent execution ... without explicit human authorization." | `src/core/operator/approvalGate.ts` — full approval gate. `offensiveSecurityAgent.ts:249-256` — wraps all tools. | ⚠️ partial | Approval gate exists and works. But auto mode bypasses all approvals (`approvalGate.ts:84-87`). All actions hardcoded to tier 1 (`approvalGate.ts:103`), no L1/L2 differentiation. |
| APTS-HO-002 | "MUST provide operators with real-time visibility into autonomous system operations." | TUI operator dashboard: `src/tui/components/operator-dashboard/`. Real-time streaming, tool call display, approval queue. | ✅ meets | TUI provides real-time tool calls, approval queue, pause/abort. |
| APTS-HO-003 | "MUST implement maximum response time windows (SLAs) and define explicit default-safe behavior if human operators fail to respond." | `approvalGate.ts:24` — `DEFAULT_DECISION_TIMEOUT_MS = 15 * 60 * 1000`. `approvalGate.ts:114-149` — timeout logic with default deny. | ✅ meets | 15-minute default timeout, configurable via `decisionTimeoutMs`, default-safe deny on timeout. |
| APTS-HO-004 | "Organizations ... MUST establish and maintain a documented Authority Delegation Matrix." | Not implemented. | ❌ gap | Organizational/policy requirement — no ADM in platform. |
| APTS-HO-006 | "MUST implement a graceful pause mechanism that allows human operators to suspend all active testing activities while preserving complete system state." | `src/core/agents/specialized/pentest/persistence.ts:659-697` — marks running subagents as "paused" with resumeInfo. Ctrl+C preserves state. | ⚠️ partial | Pause on Ctrl+C works. Missing: scheduled pause, SLA-based pause, session timeout during extended pause, scope boundary pause. |
| APTS-HO-007 | "MUST allow human operators to redirect testing scope, targets, and techniques mid-engagement." | Not implemented at tool level. Operator can type new instructions in TUI. | ⚠️ partial | Operator can give new instructions but no formal scope redirect without restart. |
| APTS-HO-008 | "MUST implement an immediate kill switch mechanism that terminates all testing activities and preserves complete system state for forensic investigation." | Two-stage Ctrl+C abort. State dump via `messages.json`, `trace.jsonl`. | ⚠️ partial | Kill exists but no encrypted state dump, no forensic sealing, no evidence hash publication. |
| APTS-HO-010 | "MUST identify and enforce mandatory human decision points before executing any action that cannot be cleanly reversed." | Approval gate applies to all tools when `requireApproval=true`. | ⚠️ partial | No distinction between reversible and irreversible actions — all or nothing. |
| APTS-HO-011 | "MUST immediately escalate to human operators" for unexpected findings. | `src/core/agents/specialized/findingJudge/` — validates findings. Document vulnerability alerts operator via TUI. | ⚠️ partial | Finding judge validates but no IoC detection, no illegal content escalation, no out-of-scope access escalation framework. |
| APTS-HO-012 | "MUST continuously monitor the actual impact of their testing activities and escalate." | Not implemented. | ❌ gap | No impact monitoring during testing. |
| APTS-HO-013 | "MUST automatically escalate the decision to human operators" when confidence < 75%. | Finding judge has confidence scores (`findingJudge/types.ts:55-56`). | ⚠️ partial | Confidence exists for findings but no scope-decision confidence or automatic escalation threshold. |
| APTS-HO-014 | "MUST identify and immediately escalate potential legal, compliance, and regulatory violations." | Not implemented. | ❌ gap | No regulatory data detection or legal escalation. |
| APTS-HO-015 | "MUST maintain a real-time activity feed of all testing actions and route notifications." | TUI operator dashboard streams all tool calls and findings. | ⚠️ partial | Real-time feed exists in TUI. No multi-channel notification (email, SMS). |

### 4. Graduated Autonomy (AL)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-AL-001–006 | L1 requirements: single technique execution, human-directed selection, parameter config, no chaining, logging, scope validation. | Approval mode (`requireApproval: true`) gates every tool call. `trace.jsonl` logs steps. Scope guard validates targets. | ⚠️ partial | With approval enabled, Apex approximates L1. But no formal autonomy level declaration, no technique selection logging with justification. |
| APTS-AL-008 | "Real-Time Human Monitoring and Approval Gates" | TUI dashboard + approval gate. | ✅ meets | Approval gate + live TUI dashboard. |
| APTS-AL-011 | "Escalation Triggers and Exception Handling" | Approval gate blocks all tool calls when enabled. | ⚠️ partial | No differentiated escalation triggers (scope violation, exploitation, data access separately). Single gate for all. |
| APTS-AL-012 | "Kill Switch and Pause Capability" | Ctrl+C abort, approval gate pause. | ⚠️ partial | Works but no formal kill switch API. |
| APTS-AL-014 | "Boundary Definition and Enforcement Framework" | `scopeGuard.ts`, session config. | ⚠️ partial | Host scope enforced. Exploitation, data, and impact boundaries not defined or enforced. |
| APTS-AL-016 | "Continuous Boundary Monitoring and Breach Detection" | `scopeGuard.ts` validates each action. | ⚠️ partial | Per-action check exists but no periodic health checks, no scope file integrity monitoring. |

### 5. Auditability (AR)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-AR-001 | "All network requests, responses, and system events MUST be logged in a structured, schema-validated format." | `src/core/agents/offSecAgent/trace.ts:35-122` — `trace.jsonl` with step records. | ⚠️ partial | Trace captures tool calls with timestamps but no schema validation, no correlation IDs, truncated outputs. |
| APTS-AR-002 | "Every transition between test phases MUST be logged." | Not implemented. | ❌ gap | No phase model or phase transition logging. |
| APTS-AR-004 | "All automated decisions MUST be logged with confidence score." | Finding judge logs confidence. Trace logs tool calls. | ⚠️ partial | Confidence scoring exists for findings. No confidence scoring on agent decisions (target selection, technique choice). |
| APTS-AR-006 | "Every multi-step attack sequence MUST document the complete chain of reasoning." | Agent conversation history in `messages.json`. | ⚠️ partial | LLM reasoning captured in messages but no structured decision chain with alternatives evaluated. |
| APTS-AR-010 | "All evidence MUST be cryptographically hashed using SHA-256." | `trace.ts:185-186` — SHA-256 hash of system prompt in init record. | ❌ gap | Only system prompt hashed. No evidence file hashing. `evidenceFiles` type has no checksum field. |
| APTS-AR-012 | "Logs MUST be stored in append-only format with cryptographic hash chains." | `trace.jsonl` is append-only. | ❌ gap | Append-only file but no hash chain, no sequence numbers, no tamper detection. |
| APTS-AR-015 | "All evidence MUST be classified based on sensitivity level." | Not implemented. | ❌ gap | No evidence classification. |

### 6. Manipulation Resistance (MR)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-MR-001 | "MUST enforce high-integrity boundaries between legitimate tool instructions and untrusted target-side content." | AI SDK separates system prompt from tool results. `scopeGuard.ts` validates URLs from tool args. | ⚠️ partial | Architectural separation via system prompt vs. assistant messages. But no cryptographic signing of operator instructions, no sandboxed parsing of target content. |
| APTS-MR-002 | "All target-side responses MUST be validated and sanitized before being processed by the tool's LLM reasoning component." | `httpRequest.ts:212` — body truncated to 5KB inline. `src/core/ai/contextManagement.ts:50-78` — tool result truncation. | ⚠️ partial | Size limiting exists. No instruction-pattern detection, no authority-claim rejection in responses. |
| APTS-MR-003 | "Custom error messages ... MUST NOT influence tool behavior." | Error messages returned as data in tool results. | ⚠️ partial | Errors treated as data but no active detection of error-based social engineering. |
| APTS-MR-004 | "Configuration files discovered during reconnaissance MUST be treated as data sources." | Config files processed by LLM as tool output. | ⚠️ partial | No specific config-file instruction detection. |
| APTS-MR-005 | "The tool MUST identify and reject any claims of authority embedded in target content." | Not implemented. | ❌ gap | No authority claim detection. |
| APTS-MR-007 | "MUST enforce a strict redirect following policy." | `httpRequest.ts:24-27` — `followRedirects` defaults to `false`. | ⚠️ partial | Redirects off by default (good). But when enabled, no scope validation on redirect destination. |
| APTS-MR-008 | "The tool MUST validate network-layer resolution results against authorized scope." | `scopeGuard.ts` validates URL host. | ⚠️ partial | URL host checked but no DNS resolution result validation, no CNAME chain checking. |
| APTS-MR-009 | "The autonomous pentesting tool MUST NOT be weaponized as an SSRF client." | `scopeGuard.ts` — URL scope check. | ⚠️ partial | URL scope helps but no explicit SSRF prevention (file://, gopher://, metadata endpoints). |
| APTS-MR-010 | "MUST detect and resist social engineering attempts embedded in target content." | Not implemented. | ❌ gap | No social engineering detection in target responses. |
| APTS-MR-011 | "The tool MUST prevent target systems from using out-of-band communication channels." | Not explicitly implemented. | ❌ gap | No OOB prevention. Email tools gated by config but no general OOB blocking. |
| APTS-MR-012 | "The tool's testing scope MUST be enforced through layered controls ... cryptographically protected." | `scopeGuard.ts` — runtime scope check. | ⚠️ partial | Scope enforced at tool level but not cryptographically signed or write-protected in memory. |
| APTS-MR-018 | "The platform MUST enforce an architectural boundary between trusted system instructions and untrusted target-derived data." | AI SDK system prompt vs. tool results separation. | ⚠️ partial | Architectural boundary exists via AI SDK message roles. No rules-engine gate between model output and action dispatch. |
| APTS-MR-019 | "When the platform discovers credentials during testing, those credentials MUST be encrypted immediately." | `src/core/credentials/manager.ts:73-74` — in-memory Map. `formatForPrompt()` returns opaque refs. | ⚠️ partial | Credential indirection design exists. But: auth-data.json writes cookies plaintext (`completeAuthentication.ts:96-107`), pentest system prompt injects raw cookies (`pentest/agent.ts:638-645`). No encryption of discovered credentials. |

### 7. Supply Chain Trust (TP)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-TP-001 | "MUST establish and document a vetting process for all external service providers." | Not in codebase (organizational). | N/A | Organizational/policy — not a platform code requirement. |
| APTS-TP-003 | "All API calls to external providers MUST use strong authentication and encryption." | `src/core/auth/signing.ts:12-24` — HMAC-SHA256 for Pensar gateway. Provider API keys stored in config. TLS via runtime. | ⚠️ partial | HMAC signing for gateway. API keys stored plaintext in `~/.pensar/config.json`. No key rotation mechanism. |
| APTS-TP-005 | "MUST establish incident response procedures for provider-related security incidents." | Not in codebase (organizational). | N/A | Organizational/policy. |
| APTS-TP-006 | "MUST maintain complete inventory of all software dependencies (SBOM)." | `package.json` + `bun.lock`. No formal SBOM. | ⚠️ partial | Lock file exists but no SPDX/CycloneDX SBOM, no vulnerability monitoring. |
| APTS-TP-008 | "MUST implement cloud security hardening." | N/A — Apex is a local CLI tool. | N/A | Apex runs locally, not on cloud infrastructure. |
| APTS-TP-012 | "MUST establish a data classification framework." | Not implemented. | ❌ gap | No data classification framework. |
| APTS-TP-013 | "MUST implement procedures to identify, protect, and report discovered sensitive data." | `src/core/credentials/manager.ts` — credential indirection. `src/core/obfuscation/` — display redaction. | ⚠️ partial | Some credential handling. No PII/PAN/PHI detection. |
| APTS-TP-014 | "MUST implement cryptographic controls to protect client data in transit and at rest." | TLS via runtime for API calls. `src/core/auth/signing.ts` — HMAC signing. | ⚠️ partial | TLS in transit. No encryption at rest for findings, credentials, session data. |
| APTS-TP-018 | "If the platform operator discovers that engagement isolation was breached ... MUST be notified." | N/A — single-user CLI tool. | N/A | Not multi-tenant. |
| APTS-TP-021 | "MUST disclose the foundation model or models powering the agent's decision-making." | `src/core/ai/models/` — model registry with explicit versioned IDs. Config stores `selectedModelId`. | ⚠️ partial | Model IDs visible in config. No formal disclosure document, no capability baseline. |

### 8. Reporting (RP)

| ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-RP-006 | "MUST disclose its false positive rate methodology." | Not implemented. | ❌ gap | No false positive rate disclosure. |
| APTS-RP-008 | "Platform reports MUST include a vulnerability coverage matrix." | Not implemented. | ❌ gap | No coverage matrix in reports. |
| APTS-RP-011 | "Every engagement report MUST include an executive summary." | `src/core/report/builder.ts:13-56` — builds report. `renderers/` — Markdown + JSON output. | ⚠️ partial | Report exists with findings summary. Missing: formal executive summary, risk posture, scope coverage percentage. |

---

## Chosen Gap: APTS-SC-004 — Rate Limiting Enforcement

### Rationale

APTS-SC-004 (Tier 1 MUST) requires: *"MUST implement hierarchical rate limiting and payload constraints for all active pentest operations [...] Per-host rate limiting: MUST implement per-host connection limits and rate limiting."*

Apex already had the infrastructure — a fully implemented `RateLimiter` class (`src/core/services/rateLimiter/index.ts`) using a token-bucket algorithm, a `requestsPerSecond` config field in `SessionConfigObject`, and a `_rateLimiter` instance created on every session. But `acquireSlot()` was never called anywhere in the codebase. The rate limiter was dead code. Every HTTP request the agent made fired at whatever rate the LLM chose, with no throttling. This directly risks denial-of-service against target systems — the core concern SC-004 addresses.

The fix is narrow (4 files, no new dependencies), safety-critical (prevents target harm), and unambiguous in its APTS requirement.

### What Changed

| File | Change |
|---|---|
| `src/core/agents/offSecAgent/tools/types.ts` | Added `rateLimiter?: RateLimiter` field to `ToolContext` |
| `src/core/agents/offSecAgent/offensiveSecurityAgent.ts` | Passes `session._rateLimiter` into `ToolContext` when building tools |
| `src/core/agents/offSecAgent/tools/httpRequest.ts` | Calls `ctx.rateLimiter.acquireSlot()` before every HTTP request |
| `src/core/services/rateLimiter/rateLimiter.test.ts` | New: unit tests for `RateLimiter` (enabled/disabled, timing, unlimited) |

### Remaining Gaps Worth Addressing

Ordered by safety impact (highest first):

1. **APTS-MR-019 / SE-023 item 10 — Credential indirection in LLM prompts.** Auth cookies and headers are injected raw into the pentest system prompt (`pentest/agent.ts:638-645`), violating credential indirection. Fix: replace with opaque references resolved at tool execution time.

2. **APTS-AR-012 — Tamper-evident logging.** `trace.jsonl` is append-only but has no hash chain. Each entry should include a sequence number and `SHA256(content + previous_hash)`.

3. **APTS-AR-010 — Evidence hashing.** Finding evidence files have no SHA-256 checksums. The `evidenceFiles` type needs a `sha256` field, computed at capture time.

4. **APTS-SC-009 — Kill switch formalization.** The two-stage Ctrl+C works but lacks Phase 1/Phase 2 timing guarantees, process tree enumeration, and remote halt capability.

5. **APTS-SE-009 — Hard deny lists.** No deny-list mechanism exists. Adding a `denyHosts` array to session config with pre-scope-check evaluation would be a focused addition.

6. **APTS-HO-001 — Approval tiers.** All actions are hardcoded to tier 1. Wiring `PermissionTier` (already defined in `operator/types.ts:17-53`) into the approval gate so different tool classes require different approval levels.

7. **APTS-SC-004 (remaining) — Per-host rate limits.** Current rate limiter is global. Per-host token buckets keyed by target hostname would fully satisfy SC-004.
