# OWASP APTS Audit — Pensar Apex

**Date:** 2026-05-18
**Standard:** [OWASP Autonomous Penetration Testing Standard (APTS) v0.1.0](https://github.com/OWASP/APTS)
**Scope:** Tier 1 (Foundation) MUST requirements — all 8 domains

---

## Audit Table

Legend: ✅ meets | ⚠️ partial | ❌ gap | N/A

### 1. Scope Enforcement (APTS-SE)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-SE-001 | "The autonomous system MUST ingest Rules of Engagement documents in a machine-parseable format and validate all scope specifications before test initialization." | `src/core/session/index.ts` L189-221 (`SessionConfigObject` schema with `scopeConstraints`); `src/tui/utils/command-flags.ts` L221-265 (CLI flags for target/scope) | ⚠️ partial | Scope is configured via CLI flags and session config (targets, allowedHosts, allowedPorts). No formal RoE document ingestion, no field completeness validation, no signature verification. |
| APTS-SE-002 | "The system MUST validate all IP ranges in scope specifications using CIDR notation parsing." | `src/core/agents/offSecAgent/tools/scopeGuard.ts` L60-137 (host-level matching via eTLD+1) | ⚠️ partial | Hostname matching exists; no CIDR notation parsing, no IPv6 support, no cloud metadata endpoint blocking, no range overlap detection. |
| APTS-SE-003 | "The system MUST validate all domain specifications in scope and MUST implement clear policies for wildcard domain handling." | `scopeGuard.ts` L37-41 (`getRegistrableDomain`), L94-108 (`isHostAllowed` with subdomain matching) | ⚠️ partial | eTLD+1 expansion acts as implicit wildcard. No explicit wildcard policy (exact vs single-level vs recursive). No third-party CDN/SaaS detection. |
| APTS-SE-004 | "The system MUST enforce temporal boundaries (start time, end time) with sufficient precision." | — | ❌ gap | No temporal boundary enforcement. No start/end time fields in session config. |
| APTS-SE-005 | "The system MUST support asset criticality classifications and MUST enforce corresponding testing restrictions." | — | ❌ gap | No asset criticality classification. No per-criticality action restrictions. |
| APTS-SE-006 | "The system MUST perform scope validation immediately before every network action." | `scopeGuard.ts` L125-137 (`assertUrlInScope`); `httpRequest.ts` L132-149; `executeCommand.ts` L169-182 | ⚠️ partial | Pre-action scope check exists for HTTP requests and shell commands. No scope check for DNS resolution results, HTTP redirects, or API calls specifically. Validation is not atomic in the APTS sense (no latency threshold). |
| APTS-SE-008 | "The system MUST continuously monitor and enforce temporal scope boundaries." | — | ❌ gap | No temporal monitoring. See SE-004. |
| APTS-SE-009 | "The system MUST maintain a hard deny list of assets that cannot be tested under any circumstance." | — | ❌ gap | No hard deny list. No immutable deny list concept. No cryptographic protection of deny lists. |
| APTS-SE-015 | "Scope enforcement audit and compliance verification." | `scopeGuard.ts` throws `ScopeViolationError` on violations (logged by agent framework) | ⚠️ partial | Scope violations are raised as errors (fail-closed). No dedicated audit report of scope enforcement compliance. |

### 2. Safety Controls (APTS-SC)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-SC-001 | "MUST implement a multi-tier impact classification system that categorizes every pentest action before execution." | `src/core/agents/specialized/cvssScorer/index.ts` (CVSS 4.0 scoring for findings); `src/core/agents/specialized/findingJudge/index.ts` (finding validation) | ⚠️ partial | CVSS scoring exists for *findings* (post-exploitation). No pre-action impact classification system. No CIA dimensional scoring before action execution. No authoritative technique-to-impact mapping. |
| APTS-SC-004 | "MUST implement hierarchical rate limiting and payload constraints for all active pentest operations." | `src/core/services/rateLimiter/index.ts` L22-98 (token-bucket `RateLimiter`); `src/core/session/index.ts` L459-461 (attached to session) | ❌ gap | RateLimiter class exists but `acquireSlot()` is never called from `http_request` or `execute_command` tools. No per-host, per-subnet, or engagement-wide rate limiting in practice. No payload size constraints. |
| APTS-SC-009 | "The platform MUST provide multiple independent kill switch mechanisms enabling immediate halt of all testing activity." | `src/tui/components/operator-dashboard/index.tsx` L204-209, L1636-1677 (Ctrl+C two-stage abort: cancel command → kill agent); `src/core/operator/approvalGate.ts` L208-212 (`denyAll()`) | ⚠️ partial | Two-stage Ctrl+C abort exists (cancel → kill). `denyAll()` denies pending approvals on kill. No remote kill switch. No automatic failsafe halt on control plane loss. No Phase 1/Phase 2 timing guarantees. No child process tracking or credential revocation. |
| APTS-SC-010 | "The platform MUST continuously monitor the health and responsiveness of target systems during testing and automatically halt testing when degradation is detected." | — | ❌ gap | No target health monitoring. No baseline calculation. No automatic halt on degradation. |
| APTS-SC-015 | "Post-test system integrity validation." | — | ❌ gap | No post-test validation. |
| APTS-SC-020 | "Action Allowlist Enforcement External to the Model." | `src/core/agents/offSecAgent/tools/index.ts` L273-387 (`ALL_TOOL_NAMES`, `PLAN_MODE_TOOL_NAMES`); `offensiveSecurityAgent.ts` L516-571 (`wrapToolsWithApprovalGate`); Zod schemas per tool | ⚠️ partial | Tool allowlisting via `activeTools` is defined in code and passed to SDK. Zod schemas validate inputs. Approval gate wraps execution. However, the allowlist is passed *to the model* via `activeTools` SDK parameter — not enforced by a separate control plane external to the model. |

### 3. Human Oversight (APTS-HO)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-HO-001 | "For autonomy levels L1 and L2, the autonomous testing system MUST implement mandatory approval gates." | `src/core/operator/approvalGate.ts` L43-240 (full approval gate with check/approve/deny/denyAll); `offensiveSecurityAgent.ts` L516-571 (`wrapToolsWithApprovalGate`); `src/tui/components/commands/operator-wizard.tsx` L52 (approval toggle) | ⚠️ partial | Approval gate exists with full workflow. All tools except `ASK_USER_QUESTIONS` go through it when enabled. However: no CVSS-based gating threshold, no differentiation by action category (exploitation vs recon), no mandatory reasoning prompts, no escalation to higher authority. Approval is binary (approve/deny) for all tools uniformly. |
| APTS-HO-002 | "Autonomous testing systems operating at L2 and above MUST provide operators with real-time visibility into autonomous system operations." | `src/tui/components/operator-dashboard/index.tsx` (full TUI with live message stream, approval queue, agent status); `src/tui/components/chat/approval-inline.tsx` (inline approval UI) | ⚠️ partial | TUI provides real-time visibility of agent actions and approval queue. Operators can pause/terminate via Ctrl+C. No scope boundary visualization, no safety control status display, no SLA tracking for approvals. |
| APTS-HO-003 | "MUST implement maximum response time windows (SLAs) and define explicit default-safe behavior if human operators fail to respond." | `approvalGate.ts` L24 (`DEFAULT_DECISION_TIMEOUT_MS = 15 * 60 * 1000`), L111-148 (timeout → deny) | ⚠️ partial | 15-minute default timeout with deny-on-timeout exists. No per-action-category SLA differentiation (exploitation vs data access vs scope boundary). No escalation progression (50% SLA → secondary approver). No client notification on extended timeout. |
| APTS-HO-004 | "MUST establish and maintain a documented Authority Delegation Matrix." | — | ❌ gap | No authority delegation matrix. Single operator model. |
| APTS-HO-006 | "MUST implement a graceful pause mechanism that allows human operators to suspend all active testing activities while preserving complete system state." | `operator-dashboard/index.tsx` L204-209 (Ctrl+C first press cancels current command); `src/core/session/index.ts` L675-842 (session resume with `getResumeMessages`) | ⚠️ partial | Ctrl+C pauses current action. Session state is persisted (`messages.json`, findings). No formal pause confirmation, no session timeout handling, no connection preservation tracking. |
| APTS-HO-007 | "MUST allow human operators to redirect testing scope, targets, and techniques mid-engagement." | `src/tui/components/operator-dashboard/` (operator can type new instructions to agent) | ⚠️ partial | Operator can redirect agent via natural language instructions mid-run. No formal scope redirect with re-validation. No technique redirect controls. |
| APTS-HO-008 | "MUST implement an immediate kill switch mechanism that terminates all testing activities and preserves complete system state." | See APTS-SC-009. `operator-dashboard/index.tsx` L1636-1677 (kill on second Ctrl+C); `approvalGate.ts` L208-212 (`denyAll`) | ⚠️ partial | Kill via double Ctrl+C. State is preserved in session files. No compressed/encrypted state dump. No forensic sealing. |
| APTS-HO-010 | "Mandatory human decision points before irreversible actions." | `approvalGate.ts` (all tools gated when approval enabled) | ⚠️ partial | When approval is enabled, all tools require human approval. No specific identification of "irreversible" actions vs reversible ones. |
| APTS-HO-011 | "Unexpected findings escalation framework." | `src/core/agents/specialized/findingJudge/index.ts` (validates findings); `documentFinding.ts` (CVSS scoring) | ⚠️ partial | Findings go through judge validation and CVSS scoring. No formal escalation framework for unexpected/critical findings. |
| APTS-HO-012 | "Impact threshold breach escalation." | — | ❌ gap | No impact threshold monitoring or escalation triggers. |
| APTS-HO-013 | "Confidence-based escalation (scope uncertainty)." | — | ❌ gap | No confidence-based scope uncertainty escalation. |
| APTS-HO-014 | "Legal and compliance escalation triggers." | — | ❌ gap | No legal/compliance trigger detection. |
| APTS-HO-015 | "Real-time activity monitoring and multi-channel notification." | TUI provides real-time activity feed | ⚠️ partial | TUI-only monitoring. No multi-channel notification (email, Slack, webhook). |

### 4. Graduated Autonomy (APTS-AL)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-AL-001 | "At Level 1, the tool MUST execute only a single, isolated attack technique per operation." | Apex operates as an AI agent with tool calls; each tool call is a single operation | ⚠️ partial | Each tool call (http_request, execute_command) is a single technique. However, the agent chains techniques via LLM reasoning without explicit L1 constraints. No formal L1 mode that prevents chaining. |
| APTS-AL-002 | "All target selection and technique selection at Level 1 MUST originate from explicit human command." | Operator initiates pentests via TUI with target specification | ⚠️ partial | Operator specifies target and objectives. Agent autonomously selects techniques. No L1 mode where operator selects each technique. |
| APTS-AL-003 | "The human operator MUST configure all technical parameters for technique execution at Level 1." | `command-flags.ts` (CLI flags for rate limit, ports, model, etc.) | ⚠️ partial | Some parameters configurable via CLI flags. Agent autonomously selects tool parameters (URLs, commands, payloads). |
| APTS-AL-004 | "No automated chaining or sequential decision-making." | Agent chains actions via LLM reasoning (by design) | ⚠️ partial | Apex is designed to chain actions (L2+). When approval is enabled, each tool call requires approval (approximating L1). No formal mode that prevents all chaining. |
| APTS-AL-005 | "Mandatory logging and human-reviewable audit trail." | `src/core/agents/offSecAgent/trace.ts` (JSONL trace with step records); `messages.json` (full message history); findings JSON files | ⚠️ partial | Structured JSONL trace log exists with observations, actions, reasoning, and usage. Now includes hash chain (APTS-AR-012). Missing: operator ID field, technique selection justification log, risk assessment acknowledgment per technique. |
| APTS-AL-006 | "Basic scope validation and policy enforcement." | `scopeGuard.ts` (assertUrlInScope, assertCommandInScope); approval gate | ⚠️ partial | Scope validation before HTTP/command execution. Approval gate for operator authorization. Missing: engagement expiry check, system state validation, concurrent operation detection. |
| APTS-AL-008 | "Real-time human monitoring and approval gates." | TUI operator dashboard + approval gate | ⚠️ partial | Real-time TUI with approval workflow. Missing: formal phase transition gates, CVSS-threshold-based gating. |
| APTS-AL-011 | "Escalation triggers and exception handling." | `approvalGate.ts` L261-265 (`ApprovalTimeoutError`); `scopeGuard.ts` `ScopeViolationError` | ⚠️ partial | Timeout → deny escalation exists. Scope violations throw errors. No configurable escalation triggers for other conditions (unusual behavior, high-impact detection, etc.). |
| APTS-AL-012 | "Kill switch and pause capability." | See APTS-SC-009 and APTS-HO-006 | ⚠️ partial | Ctrl+C two-stage kill exists. See SC-009 notes. |
| APTS-AL-014 | "Boundary definition and enforcement framework." | `scopeGuard.ts`, `SessionConfig.scopeConstraints` | ⚠️ partial | Domain-level scope boundaries defined and enforced. No depth boundaries, credential boundaries, or reporting boundaries. |
| APTS-AL-016 | "Continuous boundary monitoring and breach detection." | Scope checks before each tool call | ⚠️ partial | Pre-action scope checks per tool call. No continuous monitoring between actions, no drift detection. |

### 5. Auditability (APTS-AR)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-AR-001 | "All network requests, responses, and system events MUST be logged in a structured, schema-validated format." | `trace.ts` L35-122 (`StepRecord` with timestamp, agentId, observations, actions, usage) | ⚠️ partial | Structured JSONL log exists with ISO 8601 timestamps. Event type (`type` field), observations, and actions are captured. Missing: correlation ID across related events, formal schema validation at write time, network-specific fields (target, method, status_code, duration_ms). |
| APTS-AR-002 | "Every transition between test phases MUST be logged." | `trace.ts` L128-168 (`StateCheckpoint` with assessment, actionsAttempted, nextSteps) | ⚠️ partial | Checkpoint records capture agent state snapshots. Missing: explicit phase transition events with previous_state/new_state/triggering_condition using APTS canonical phases. |
| APTS-AR-004 | "All automated decisions MUST be logged with confidence score (0.0-1.0)." | `trace.ts` L35-122 (StepRecord captures reasoning, text, actions); `findingJudge` returns confidence for findings | ⚠️ partial | Agent reasoning is captured in trace. Finding judge provides confidence scores. Missing: per-decision confidence scores, alternatives evaluated, fallback actions, minimum confidence thresholds by action type. |
| APTS-AR-006 | "Every multi-step attack sequence MUST document the complete chain of reasoning." | `trace.ts` StepRecord.reasoning, StepRecord.text, StateCheckpoint | ⚠️ partial | Reasoning and text captured per step. Missing: explicit decision points, alternative path documentation, rejection categories. |
| APTS-AR-010 | "All evidence MUST be cryptographically hashed using SHA-256." | `documentFinding.ts` L407-414 (findings persisted as JSON files) | ❌ gap | Finding JSON files are written without SHA-256 hashes. No hash stored alongside evidence. No algorithm identification. |
| APTS-AR-012 | "Logs MUST be stored in append-only format with cryptographic hash chains." | `trace.ts` `appendRecord()` with hash chain (seq, prevHash, hash); `verifyTraceChain()` | ✅ meets | **Fixed in this session.** Each trace record now includes: monotonically increasing `seq`, `prevHash` (SHA-256 of prior record), `hash` (SHA-256 of content + prevHash). `verifyTraceChain()` implements the APTS-AR-012 Chain Verification Algorithm. Genesis sentinel for first record. |
| APTS-AR-015 | "Evidence classification and sensitive data handling." | `src/core/credentials/manager.ts` L150-159 (secrets only at tool execution, never serialized) | ⚠️ partial | Credential secrets are protected (never serialized to disk). No formal data classification framework (RESTRICTED/CONFIDENTIAL/INTERNAL/PUBLIC). |

### 6. Manipulation Resistance (APTS-MR)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-MR-001 | "The autonomous pentesting tool MUST enforce high-integrity boundaries between legitimate tool instructions and untrusted target-side content." | Agent architecture separates system prompt (operator instructions) from tool results (target content) via AI SDK message roles | ⚠️ partial | System/assistant/tool message separation via AI SDK. Operator instructions in system prompt. Target content in tool results. No cryptographic signing of operator instructions. No sandboxed parsing of target content. |
| APTS-MR-002 | "All target-side responses MUST be validated and sanitized before being processed by the tool's LLM reasoning component." | Tool results are passed directly to the LLM context | ❌ gap | No response sanitization before LLM processing. Target-side content (HTTP responses, command output) flows directly into LLM context without injection detection. |
| APTS-MR-003 | "Custom error messages MUST NOT influence tool behavior." | Error messages treated as tool output | ⚠️ partial | Errors are returned as tool results (data, not instructions). LLM could still be influenced by error content. |
| APTS-MR-004 | "Configuration files discovered during reconnaissance MUST be treated as data sources, not directives." | Agent processes config files as part of reconnaissance | ⚠️ partial | Config files are analyzed for vulnerabilities by the LLM. No explicit protection against instruction injection via discovered configs. |
| APTS-MR-005 | "The tool MUST identify and reject any claims of authority embedded in target content." | — | ❌ gap | No authority claim detection in target responses. |
| APTS-MR-007 | "The autonomous pentesting tool MUST enforce a strict redirect following policy." | `scopeGuard.ts` checks scope for HTTP requests | ⚠️ partial | Scope validation on HTTP requests. No explicit redirect chain validation (redirects handled by curl/browser in sandbox). |
| APTS-MR-008 | "The tool MUST validate network-layer resolution results against authorized scope." | `scopeGuard.ts` validates hostnames before connections | ⚠️ partial | Hostname validation exists. No DNS resolution result validation, no DNSSEC, no DNS-over-HTTPS. |
| APTS-MR-009 | "The autonomous pentesting tool MUST NOT be weaponized as an SSRF client." | `scopeGuard.ts` L125-137 (scope check before HTTP); `executeCommand.ts` L169-182 (scope check before commands) | ⚠️ partial | Scope checks prevent contacting out-of-scope hosts. No explicit file:// scheme blocking, no cloud metadata endpoint blocking in scope guard. |
| APTS-MR-010 | "The tool MUST detect and resist social engineering attempts embedded in target content." | — | ❌ gap | No social engineering detection in target responses. Relies on LLM system prompt instructions. |
| APTS-MR-011 | "Out-of-band communication prevention." | — | ❌ gap | No OOB communication prevention (no outbound network restriction on agent). |
| APTS-MR-012 | "Immutable scope enforcement architecture." | `scopeGuard.ts` reads scope from session config at each check | ⚠️ partial | Scope derived from session config. Agent cannot modify scope. However, scope is not cryptographically sealed or write-protected at OS level. |
| APTS-MR-018 | "AI model input/output architectural boundary." | AI SDK separates system prompt, tool definitions, and tool results into distinct message roles | ⚠️ partial | Message role separation exists. No formal I/O boundary between model reasoning and target data at the architectural level. |
| APTS-MR-019 | "Discovered credential protection." | `src/core/credentials/manager.ts` L73-243 (CredentialManager with secure storage, `formatForPrompt` safe refs, secrets never serialized) | ⚠️ partial | Credentials stored in-memory, never serialized to disk. Safe reference formatting for prompts. However: agent can use `execute_command` to use discovered credentials without explicit operator approval of credential usage. |

### 7. Supply Chain Trust (APTS-TP)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-TP-001 | "Organizations MUST establish and document a vetting process for all external service providers." | N/A | N/A | Organizational process, not a codebase artifact. Apex supports multiple AI providers with documented selection. |
| APTS-TP-003 | "All API calls to external providers MUST use strong authentication and encryption." | `src/core/ai/utils.ts` L81-111 (`buildAuthConfig` with API keys); provider SDKs use HTTPS by default | ⚠️ partial | API keys used for auth. TLS enforced by provider SDKs. No key rotation schedule in code. No mutual TLS. |
| APTS-TP-005 | "Organizations MUST establish incident response procedures for provider-related security incidents." | N/A | N/A | Organizational process. |
| APTS-TP-006 | "Organizations MUST maintain complete inventory of all software dependencies (SBOM)." | `bun.lock` (dependency lockfile); `package.json` | ⚠️ partial | Lockfile exists. No formal SBOM generation. No vulnerability monitoring integration. No typosquatting detection. |
| APTS-TP-008 | "Organizations MUST implement cloud security hardening." | N/A | N/A | Apex is a local CLI tool, not a cloud-deployed service. Cloud security applies to deployment context, not the CLI itself. |
| APTS-TP-012 | "Organizations MUST establish a data classification framework." | `src/core/credentials/manager.ts` (credential handling); no formal framework | ❌ gap | No formal data classification framework. Credentials are treated specially but no RESTRICTED/CONFIDENTIAL/INTERNAL/PUBLIC taxonomy. |
| APTS-TP-013 | "Sensitive data discovery and handling." | CredentialManager; agent prompts instruct careful handling | ⚠️ partial | Credentials discovered by agent are managed via CredentialManager. No automated PII detection or redaction before AI provider calls. |
| APTS-TP-014 | "Data encryption and cryptographic controls." | Credentials in-memory only (never on disk); session data stored as plaintext JSON | ⚠️ partial | Credentials never persisted. Session data (findings, trace, messages) stored as plaintext JSON files. No encryption at rest for session artifacts. |
| APTS-TP-021 | "Foundation model disclosure and capability baseline." | `src/core/ai/models/index.ts` (`AVAILABLE_MODELS` registry with model IDs) | ⚠️ partial | Model identifiers tracked in registry. No formal capability baseline documentation. No disclosure document. |

### 8. Reporting (APTS-RP)

| Requirement ID | Requirement | Apex Evidence | Status | Notes |
|---|---|---|---|---|
| APTS-RP-006 | "The platform MUST disclose its false positive rate methodology and measurements." | `src/core/agents/specialized/findingJudge/index.ts` (validates findings, returns confidence) | ❌ gap | No false positive rate disclosure. No methodology documentation. No customer feedback mechanism. |
| APTS-RP-008 | "Platform reports MUST include a vulnerability coverage matrix." | — | ❌ gap | No coverage matrix. No CWE mapping of tested vulnerability classes. |
| APTS-RP-011 | "Every engagement report MUST include an executive summary." | `src/core/api/blackboxPentest.ts` L21-31 (returns findings, paths, reportPath); findings have severity/CVSS | ⚠️ partial | Findings include severity and CVSS scores. Report generation exists. No formal executive summary section. No machine-readable report format (JSON/XML). |

---

## Chosen Gap: APTS-AR-012 — Tamper-Evident Logging with Hash Chains

### Rationale

APTS-AR-012 is a **MUST | Tier 1** requirement in the Auditability domain. The requirement states:

> "Logs MUST be stored in append-only format with cryptographic hash chains preventing undetected modification. Each log entry includes a monotonically increasing entry sequence number AND the hash of the previous entry."

Apex already has a well-structured append-only trace log (`trace.jsonl`) with rich step/checkpoint/task records — but it had zero tamper evidence. Any post-hoc modification to trace records was undetectable. This is a foundational auditability gap: without hash chains, the entire audit trail is only as trustworthy as filesystem permissions allow.

This gap was chosen because:
1. **Unambiguous APTS requirement** with a concrete verification algorithm
2. **Real gap** — no hash chain or sequence numbering existed
3. **Scoped fix** — touches only `trace.ts` and `trace.test.ts` (2 files)
4. **Safety/auditability priority** — tamper-evident logging underpins every other auditability requirement

### What Changed

**`src/core/agents/offSecAgent/trace.ts`:**
- Added `HashChainEnvelope` type with `seq`, `prevHash`, `hash` fields
- Added `SerializedTraceRecord` type (domain record + chain envelope)
- Added `HASH_CHAIN_GENESIS` sentinel constant
- Added `computeRecordHash(contentJson, prevHash)` — exported for external verification
- Modified `StepTraceWriter.appendRecord()` to compute and inject chain fields
- Added `verifyTraceChain(tracePath)` implementing the APTS-AR-012 Chain Verification Algorithm

**`src/core/agents/offSecAgent/trace.test.ts`:**
- Added `readSerializedRecords()` helper for chain-aware assertions
- Added 13 new tests:
  - Every record has seq/hash/prevHash fields
  - Continuous sequence numbers across all record types
  - First record uses genesis sentinel
  - Each prevHash matches previous record's hash
  - Hash is deterministically computed from content + prevHash
  - `verifyTraceChain` succeeds on valid trace
  - `verifyTraceChain` detects content modification (tamper)
  - `verifyTraceChain` detects deletion (sequence gap)
  - Edge cases: empty file, non-existent file

All 1016 tests pass. No new dependencies.

---

## Remaining Gaps Worth Addressing (prioritized)

1. **APTS-SC-004: Rate limiter not wired** — `RateLimiter` exists but `acquireSlot()` is never called from tools. Quick fix: wire it into `http_request` and `execute_command`.

2. **APTS-AR-010: Evidence hashing** — Findings are persisted as JSON but with no SHA-256 hashes. Add hash computation in `documentFinding.ts` when writing finding JSON/evidence files.

3. **APTS-SE-009: Hard deny lists** — No deny list concept. Add a `denyList` field to `SessionConfig.scopeConstraints` checked before `allowedHosts` in `scopeGuard.ts`.

4. **APTS-MR-002: Response sanitization** — Target-side content flows directly to LLM without injection detection. Add a sanitization layer between tool results and LLM context.

5. **APTS-SE-004/008: Temporal boundaries** — No start/end time enforcement. Add temporal fields to session config and check them in the agent loop.

6. **APTS-SC-020: External action allowlist** — Tool allowlisting is passed to the model via SDK `activeTools`. Add an independent validation layer that checks tool calls against the allowlist before execution, external to the LLM.

7. **APTS-HO-003: Per-action-category SLA** — Approval timeout is uniform (15 min). Differentiate by action risk level per the APTS SLA table.

8. **APTS-RP-006/008: Reporting gaps** — No false positive rate disclosure or coverage matrix. Requires new report generation infrastructure.
