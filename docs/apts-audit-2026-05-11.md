# OWASP APTS Audit — Pensar Apex

**Date:** 2026-05-11
**Standard:** [OWASP Autonomous Penetration Testing Standard (APTS) v0.1.0](https://github.com/OWASP/APTS)
**Scope:** Apex codebase at branch `cursor/apex-apts-audit-19ae`

---

## 1. Audit Table

Focus: Tier 1 MUST requirements (the foundation tier). Tier 2+ requirements are included where Apex has relevant evidence. Requirements marked N/A have documented reasoning.

### 1.1 Scope Enforcement (APTS-SE)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-SE-001 | "The autonomous system MUST ingest Rules of Engagement documents in a machine-parseable format and validate all scope specifications before test initialization." | `src/core/session/index.ts:191-223` — `SessionConfigObject` with `scopeConstraints`, targets, `allowedHosts`. No structured RoE schema, no authorization proof, no escalation procedures field. | ⚠️ partial | Session config captures target list and allowed hosts. Missing: machine-parseable RoE format with all required fields (temporal boundaries, action restrictions, authorization proof, escalation procedures). |
| APTS-SE-002 | "The system MUST validate all IP ranges in scope specifications using CIDR notation parsing." | No CIDR parsing or IP range validation. `scopeGuard.ts` operates on hostnames only. | ❌ gap | No IP-level scope enforcement. |
| APTS-SE-003 | "The system MUST validate all domain specifications in scope and MUST implement clear policies for wildcard domain handling." | `src/core/agents/offSecAgent/tools/scopeGuard.ts:37-41` — eTLD+1 expansion via `tldts`; `isHostAllowed` at line 94-109 for subdomain matching. | ⚠️ partial | Domain validation and subdomain matching exist. Missing: explicit wildcard policies (exact vs. single-level vs. all), third-party infrastructure detection, CNAME resolution checks. |
| APTS-SE-004 | "The system MUST enforce temporal boundaries (start time, end time) with sufficient precision." | No temporal boundary fields in session config. | ❌ gap | No time-window enforcement. |
| APTS-SE-005 | "The system MUST support asset criticality classifications." | No criticality classification in session config or scope guard. | ❌ gap | |
| APTS-SE-006 | "The system MUST perform scope validation immediately before every network action." | `scopeGuard.ts:125-137` — `assertUrlInScope` called in `http_request` (line 132-149 of httpRequest.ts) and `assertCommandInScope` in `execute_command` (line 169-182 of executeCommand.ts). | ⚠️ partial | Pre-action scope check exists for HTTP and command tools. Missing: DNS resolution validation, redirect following validation (done at hostname level only), cloud API validation, <100ms SLA tracking. |
| APTS-SE-009 | "The system MUST maintain a hard deny list of assets that cannot be tested under any circumstance." | No deny list mechanism. Only allowlist-style scoping. | ❌ gap | |
| APTS-SE-015 | "Scope enforcement audit and compliance verification" | `trace.ts` logs tool calls and scope violations are thrown as errors. No dedicated scope audit report. | ⚠️ partial | Scope violations throw `ScopeViolationError` which is logged in trace. No compliance verification tooling. |
| APTS-SE-019 | "Rate Limiting, Adaptive Backoff, and Production Impact Controls" | `src/core/session/index.ts:463-465` — `RateLimiter` instantiated but not wired to tools. `src/core/services/rateLimiter/index.ts` exists but unused in `http_request` or `execute_command`. | ❌ gap | Rate limiter code exists but is not connected to outbound tool actions. |
| APTS-SE-023 | "Credential and Secret Lifecycle Governance" | `src/core/credentials/manager.ts` — in-memory credential store, ID-based references, secrets resolved only at tool execution time. Not serialized with session. | ⚠️ partial | Good credential isolation (references vs secrets). Missing: credential rotation, expiry, revocation on engagement end. |

### 1.2 Safety Controls (APTS-SC)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-SC-001 | "MUST implement a multi-tier impact classification system that categorizes every pentest action before execution." | No impact classification system. Individual tools don't have impact tiers. | ❌ gap | |
| APTS-SC-004 | "MUST implement hierarchical rate limiting and payload constraints." | Rate limiter exists but not wired. No payload size constraints. | ❌ gap | |
| APTS-SC-009 | "The platform MUST provide multiple independent kill switch mechanisms enabling immediate halt of all testing activity." | `src/tui/components/operator-dashboard/index.tsx:1654-1667` — Ctrl+C two-stage abort. `src/tui/components/operator-dashboard/logic.ts:178-215` — abort handler denies pending approvals, aborts controller. | ⚠️ partial | Single kill switch (Ctrl+C). Missing: remote kill, auto-failsafe on lost control plane, Phase 1/2 timing guarantees, process tree termination, credential revocation. |
| APTS-SC-010 | "The platform MUST continuously monitor the health and responsiveness of target systems during testing." | No health check monitoring of targets. | ❌ gap | |
| APTS-SC-015 | "Post-Test System Integrity Validation" | No post-test validation mechanism. | ❌ gap | |
| APTS-SC-019 | "Execution Sandbox and Containment Boundary Integrity" | `src/core/agents/offSecAgent/tools/sandbox.ts:30-36` — `UnifiedSandbox` interface. Commands routed through sandbox in `executeCommand.ts:184-215`. | ⚠️ partial | Sandbox interface exists and is used. No containment boundary verification or escape detection. |
| APTS-SC-020 | "Action Allowlist Enforcement External to the Model" | `src/core/agents/offSecAgent/tools/index.ts:332-384` — `PLAN_MODE_TOOL_NAMES` and `ALL_TOOL_NAMES`. `offensiveSecurityAgent.ts:270-274` — plan mode intersects with allowlist. `activeTools` passed to AI SDK. | ⚠️ partial | Tool allowlists exist and are enforced at the AI SDK level (tools not in `activeTools` cannot be called). Enforcement is at the SDK boundary, not a separate runtime layer. |

### 1.3 Human Oversight (APTS-HO)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-HO-001 | "Mandatory Pre-Approval Gates for Autonomy Levels L1 and L2" | `src/core/operator/approvalGate.ts:79-91` — `check()` blocks until operator approves/denies. `offensiveSecurityAgent.ts:479-534` — all tools wrapped with approval gate (except exempt tools). | ⚠️ partial | Approval gates exist for all tools. Missing: CVSS-based gating, different gate levels per action category, immutable approval records with rationale. Approval history is in-memory only (capped at 100 entries). |
| APTS-HO-002 | "Real-Time Monitoring and Intervention Capability" | `src/tui/components/operator-dashboard/` — real-time TUI showing active operations, pending approvals. Operator can pause/terminate. | ⚠️ partial | TUI provides real-time visibility and intervention. Missing: dashboard access logging, 90-day log retention, intervention logging with operator identity. |
| APTS-HO-003 | "Decision Timeout and Default-Safe Behavior" | `approvalGate.ts:24` — `DEFAULT_DECISION_TIMEOUT_MS = 15 * 60 * 1000` (15 min). `approvalGate.ts:125-149` — timeout resolves to deny. | ⚠️ partial | Default-safe deny on timeout exists. Missing: per-action-category SLA table, escalation progression at 50% SLA, client notification at 30 min. |
| APTS-HO-006 | "Graceful Pause Mechanism with State Preservation" | `src/core/session/persistence.ts` — `saveSubagentData`, manifest persistence. `offensiveSecurityAgent.ts:276-310` — `messages.json` debounced persistence. Ctrl+C triggers abort. | ⚠️ partial | Session state and messages are persisted. Missing: formal pause/resume workflow, connection preservation, session timeout during pause. |
| APTS-HO-008 | "Immediate Kill Switch with State Dump" | Ctrl+C abort exists. No state dump on kill. | ⚠️ partial | See APTS-SC-009 notes. No forensic state dump. |
| APTS-HO-010 | "Mandatory Human Decision Points Before Irreversible Actions" | ApprovalGate applies uniformly when enabled — no special handling for irreversible actions specifically. | ⚠️ partial | All actions gated when approval is on. Missing: irreversibility classification per action. |
| APTS-HO-011 | "Unexpected Findings Escalation Framework" | `src/core/agents/offSecAgent/tools/documentFinding.ts` — finding judge validates findings. `ask_user_questions` tool can pause for operator input. | ⚠️ partial | Findings go through validation. No automatic escalation to operator for unexpected/critical findings. |
| APTS-HO-013 | "Confidence-Based Escalation (Scope Uncertainty)" | No confidence-based scope escalation. | ❌ gap | |
| APTS-HO-015 | "Real-Time Activity Monitoring and Multi-Channel Notification" | TUI dashboard shows real-time activity. No multi-channel notification (email, Slack, etc.). | ⚠️ partial | |

### 1.4 Graduated Autonomy (APTS-AL)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-AL-001 | "At Level 1 Assisted autonomy, the tool MUST execute only a single, isolated attack technique per operation." | Apex operates primarily at L2+ — the LLM chains multiple tool calls per step. In operator "manual" mode with approval, each tool call is individually gated. | ⚠️ partial | Manual mode + approval gate gives L1-like behavior. No formal L1 mode that prevents chaining. |
| APTS-AL-005 | "Every action at Level 1 MUST be logged with complete information enabling human review." | `trace.ts` — step records capture tool calls, inputs (preview), outputs (preview), timestamps, model, usage. | ⚠️ partial | Structured logging exists. Missing: operator ID per action, stated justification, risk assessment acknowledgment. |
| APTS-AL-006 | "Before executing any technique at Level 1, the tool MUST validate target scope, technique policy, engagement validity." | `scopeGuard.ts` — target scope validation. No technique policy or engagement validity checks. | ⚠️ partial | Scope validation exists. Missing: technique allowlist enforcement, engagement expiry check. |
| APTS-AL-008 | "At Level 2, the tool MUST maintain continuous connection to human operator(s) with real-time capability." | TUI operator dashboard with real-time view, approval queue, intervention capability. | ⚠️ partial | Core L2 capability exists. Missing: formal phase transition approval gates. |
| APTS-AL-011 | "The tool MUST be configured with explicit escalation triggers and exception handling." | `ApprovalGate` timeout escalation exists. No configurable escalation triggers. | ⚠️ partial | |
| APTS-AL-012 | "Kill Switch and Pause Capability" | Ctrl+C abort. See APTS-SC-009. | ⚠️ partial | |
| APTS-AL-014 | "Boundary Definition and Enforcement Framework" | `scopeGuard.ts` + `sessionConfig.scopeConstraints`. | ⚠️ partial | Host-level boundaries only. |

### 1.5 Auditability (APTS-AR)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-AR-001 | "All network requests, responses, and system events MUST be logged in a structured, schema-validated format with timestamps precise to millisecond or better." | `trace.ts:35-122` — `StepRecord` with ISO 8601 timestamps, tool call/result logging, step indices. Correlation via `agentId` + `stepIndex`. | ⚠️ partial | Structured step-level logging exists with ms timestamps. Missing: schema validation at write time, per-network-request granularity (trace logs at step level, not per-request), correlation IDs. |
| APTS-AR-002 | "Every transition between test phases MUST be logged." | `trace.ts:128-168` — `StateCheckpoint` records. No formal phase model (Recon→Enum→Exploit etc.). | ⚠️ partial | Checkpoint records exist but are agent-driven, not tied to APTS canonical phase model. |
| APTS-AR-004 | "All automated decisions MUST be logged with confidence score (0.0-1.0)." | `src/core/agents/specialized/findingJudge/index.ts:76-92` — finding judge outputs confidence 0-1. Trace records capture model reasoning. | ⚠️ partial | Finding-level confidence exists. Missing: per-decision confidence scoring for all automated decisions, minimum thresholds per action type. |
| APTS-AR-006 | "Every multi-step attack sequence MUST document the complete chain of reasoning." | `trace.ts` — reasoning parts captured per step. `StateCheckpoint` records capture assessment. | ⚠️ partial | Reasoning captured. Missing: structured alternative evaluation with rejection categories. |
| APTS-AR-010 | "All evidence MUST be cryptographically hashed using SHA-256 (minimum)." | `trace.ts:386-389` — SHA-256 hash of system prompt (12-char prefix only). No evidence hashing on findings or artifacts. | ❌ gap | System prompt gets a truncated hash. Finding evidence, HTTP responses, and artifacts are not hashed. |
| APTS-AR-012 | "Logs MUST be stored in append-only format with cryptographic hash chains." | **FIXED:** `trace.ts` — `HashChainFields` (seq, previousHash, hash) on all records. `appendRecord()` computes SHA-256 chain. `verifyTraceChain()` for offline verification. | ✅ meets | Implemented in this audit session. |
| APTS-AR-015 | "Evidence Classification and Sensitive Data Handling" | `src/core/credentials/manager.ts` — credential references vs secrets separation. No formal evidence classification. | ⚠️ partial | Credential data is separated. No classification labels on evidence. |
| APTS-AR-020 | "Audit Trail Isolation from the Agent Runtime" | `trace.ts` — trace file is written by `appendFileSync` from within the agent process. Agent could theoretically modify trace. | ❌ gap | Audit trail not isolated from agent runtime. |

### 1.6 Manipulation Resistance (APTS-MR)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-MR-001 | "The autonomous pentesting tool MUST enforce high-integrity boundaries between legitimate tool instructions and untrusted target-side content." | Agent system prompts are separate from target data. No cryptographic signing of operator instructions. Target content processed by LLM in shared context. | ⚠️ partial | Architectural separation exists (system prompt vs tool results). Shared LLM context means no hard boundary. |
| APTS-MR-002 | "All target-side responses MUST be validated and sanitized before being processed by the tool's LLM reasoning component." | No sanitization layer between target responses and LLM context. | ❌ gap | |
| APTS-MR-004 | "Configuration File Integrity Verification" | No integrity verification of config files (`~/.pensar/`). | ❌ gap | |
| APTS-MR-007 | "The autonomous pentesting tool MUST enforce a strict redirect following policy." | `scopeGuard.ts:assertUrlInScope` — scope check applies to URLs but no explicit redirect-following policy in `http_request` tool. | ⚠️ partial | Scope checks URLs but no redirect chain validation or loop detection. |
| APTS-MR-012 | "Immutable Scope Enforcement Architecture" | `scopeGuard.ts` scope is derived from session config at check time. Session config could be mutated during run. | ❌ gap | Scope is not immutable during execution. |
| APTS-MR-019 | "Discovered Credential Protection" | `credentials/manager.ts` — in-memory only, ID-based references, secrets resolved only at tool execution. Not serialized to disk. | ✅ meets | Credentials are protected: in-memory only, never serialized, prompt-safe references used everywhere. |

### 1.7 Supply Chain Trust (APTS-TP)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-TP-003 | "All API calls to external providers MUST use strong authentication and encryption." | `src/core/ai/` — API keys managed via environment variables and config. TLS used by default (AI SDK uses HTTPS). | ⚠️ partial | TLS and API key auth in place. Missing: key rotation schedule, mutual TLS, usage monitoring. |
| APTS-TP-006 | "Organizations MUST maintain complete inventory of all software dependencies (SBOM)." | `bun.lock` exists. No formal SBOM document, no vulnerability monitoring process documented. | ⚠️ partial | Lock file exists. No SBOM generation or vulnerability scanning. |
| APTS-TP-012 | "Organizations MUST establish a data classification framework." | No data classification framework. | ❌ gap | |
| APTS-TP-013 | "Sensitive Data Discovery and Handling" | Credential manager separates secrets from references. No automated PII/sensitive data discovery. | ⚠️ partial | |
| APTS-TP-014 | "Data Encryption and Cryptographic Controls" | Session data stored unencrypted on disk (`~/.pensar/sessions/`). | ❌ gap | |
| APTS-TP-021 | "Foundation Model Disclosure and Capability Baseline" | `src/core/ai/models/` — model catalog with IDs. Model recorded in trace init. | ⚠️ partial | Models are tracked. No formal capability baseline or customer disclosure document. |

### 1.8 Reporting (APTS-RP)

| Req ID | Requirement (quoted) | Apex Evidence | Status | Notes |
|--------|---------------------|---------------|--------|-------|
| APTS-RP-006 | "The platform MUST disclose its false positive rate methodology and measurements." | No false positive rate tracking or disclosure. | ❌ gap | |
| APTS-RP-008 | "Platform reports MUST include a vulnerability coverage matrix." | `findings-summary.md` generated per session. No coverage matrix. | ❌ gap | |
| APTS-RP-011 | "Every engagement report MUST include an executive summary suitable for non-technical stakeholders." | `documentFinding.ts` generates per-finding markdown + JSON. `findings-summary.md` aggregates. No executive summary. | ⚠️ partial | Finding reports exist. No executive summary with risk overview. |

---

## 2. Chosen Gap: APTS-AR-012 — Tamper-Evident Logging with Hash Chains

### Rationale

APTS-AR-012 is a **Tier 1 MUST** requirement that states:

> "Logs MUST be stored in append-only format with cryptographic hash chains preventing undetected modification. [...] Each log entry includes a monotonically increasing entry sequence number AND the hash of the previous entry. [...] Format: Chain of SHA-256 hashes linking entries."
>
> — `standard/5_Auditability/README.md#apts-ar-012-tamper-evident-logging-with-hash-chains`

Apex's `trace.jsonl` was already append-only and structured, but had **no hash chain** linking entries. This meant a modified or deleted log entry would be undetectable. Adding hash chains makes the audit trail tamper-evident — a prerequisite for every other auditability requirement. The fix is surgical (one module + its tests), requires no new dependencies (Node's `crypto` is already imported), and directly serves the safety/auditability mission that APTS prioritizes.

---

## 3. What Changed

### Files modified (3 files)

1. **`src/core/agents/offSecAgent/trace.ts`**
   - Added `HashChainFields` interface (`seq`, `previousHash`, `hash`) — all four trace record types now extend it
   - `StepTraceWriter` maintains `seq` counter and `previousHash` state
   - `appendRecord()` computes SHA-256 hash chain: sets `seq`, `previousHash`, computes `hash` over all fields (excluding `hash` itself), then writes
   - Added `verifyTraceChain()` function for offline chain verification per the APTS-AR-012 verification algorithm
   - Updated `CheckpointInput`, `TaskRecordInput`, and `writeInit` parameter types to omit hash chain fields (filled by writer)

2. **`src/core/agents/offSecAgent/trace.test.ts`**
   - 11 new tests covering: hash chain field presence, sequence numbering, previousHash linkage, hash computation, `verifyTraceChain` validation (valid chain, content tampering, deleted records, broken links, empty input, task record participation)

3. **`src/core/agents/offSecAgent/index.ts`**
   - Exported `HashChainFields`, `ChainVerificationResult` types and `verifyTraceChain` function

### Test results

- All 995 tests pass (38 in trace.test.ts, 11 new)
- TypeScript type check clean
- Biome lint clean on changed files

---

## 4. Remaining Gaps Worth Addressing

Priority-ordered by safety impact and feasibility:

1. **APTS-AR-010 — Cryptographic Hashing of All Evidence**: Finding evidence (HTTP responses, POC outputs, artifacts) is not SHA-256 hashed. Fix: hash evidence content in `documentFinding.ts` and store alongside findings JSON. ~2 files.

2. **APTS-SC-009/HO-008 — Kill Switch with State Dump**: Ctrl+C abort exists but lacks Phase 1/2 timing guarantees, process tree termination, credential revocation, and forensic state dump. Fix: formalize the abort handler with timed phases. ~3-4 files.

3. **APTS-SE-009 — Hard Deny Lists**: No deny list mechanism. Fix: add a `deniedHosts` field to `ScopeConstraints` and check it before allowlist in `scopeGuard.ts`. ~2 files.

4. **APTS-AR-020 — Audit Trail Isolation from Agent Runtime**: Trace is written from within the agent process. Fix: write to a separate process/pipe or use OS-level file permissions. More invasive.

5. **APTS-SE-004 — Temporal Boundaries**: No engagement time window enforcement. Fix: add `startTime`/`endTime` to session config and check before each tool call. ~3 files.

6. **APTS-MR-012 — Immutable Scope**: Scope derived from mutable session config. Fix: freeze scope at session creation, make `allowedHosts` readonly. ~2 files.

7. **APTS-SC-020 — External Action Allowlist**: Tool allowlist is enforced at the AI SDK boundary. A defense-in-depth approach would add a second enforcement layer outside the model call. ~2-3 files.

8. **APTS-SE-019 — Rate Limiting**: `RateLimiter` exists but is not wired to outbound tools. Fix: inject rate limiter into `http_request` and `execute_command`. ~2 files.
