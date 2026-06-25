/**
 * CVSS 4.0 Scorer Subagent
 *
 * A specialized agent that analyzes vulnerability findings and their discovery context
 * to determine appropriate CVSS 4.0 metrics and calculate scores.
 *
 * This agent is spawned by the document_vulnerability tool to provide standardized
 * severity scoring based on the CVSS 4.0 specification.
 */

import { z } from "zod";
import { type CVSS4Metrics, calculateCVSS4Score } from "../../../../lib/cvss";
import {
  CweEntrySchema,
  type ValidatedCweEntry,
} from "../../../../lib/cwe/types";
import { validateCweEntries } from "../../../../lib/cwe/validate";
import {
  type AIAuthConfig,
  type AIModel,
  generateObjectResponse,
} from "../../../ai";

// =============================================================================
// Types
// =============================================================================

export interface CVSSScorerInput {
  /** The finding to score */
  finding: {
    title: string;
    description: string;
    impact: string;
    evidence: string;
    endpoint: string;
    vulnerabilityClass?: string;
    remediation?: string;
  };
  /** Messages from the meta testing agent's conversation (for context) */
  agentMessages: Record<string, unknown>[];
}

export interface CVSSScorerResult {
  /** Numeric score (0.0-10.0) */
  score: number;
  /** Qualitative severity (NONE, LOW, MEDIUM, HIGH, CRITICAL) */
  severity: string;
  /** Full vector string (CVSS:4.0/AV:N/...) */
  vectorString: string;
  /** Individual metric values */
  metrics: CVSS4Metrics;
  /** Score type (CVSS-B, CVSS-BT, etc.) */
  scoreType: string;
  /** AI's reasoning for metric choices */
  reasoning: string;
  /** CWE classifications assigned to this vulnerability (validated against MITRE database) */
  cwes: ValidatedCweEntry[];
}

// =============================================================================
// Schema for AI Output
// =============================================================================

const CVSSMetricsOutputSchema = z.object({
  metrics: z.object({
    // Base Metrics - Exploitability
    AV: z
      .enum(["N", "A", "L", "P"])
      .describe(
        "Attack Vector: N=Network (remotely exploitable), A=Adjacent network, L=Local access required, P=Physical access required",
      ),
    AC: z
      .enum(["L", "H"])
      .describe(
        "Attack Complexity: L=Low (no special conditions), H=High (requires specific conditions/bypassing)",
      ),
    AT: z
      .enum(["N", "P"])
      .describe(
        "Attack Requirements: N=None (works in most configs), P=Present (requires race conditions/specific setup)",
      ),
    PR: z
      .enum(["N", "L", "H"])
      .describe(
        "Privileges Required: N=None (unauthenticated), L=Low (basic user), H=High (admin)",
      ),
    UI: z
      .enum(["N", "P", "A"])
      .describe(
        "User Interaction: N=None, P=Passive (user visits page), A=Active (user must click/interact)",
      ),

    // Base Metrics - Vulnerable System Impact
    VC: z
      .enum(["H", "L", "N"])
      .describe(
        "Confidentiality Impact on Vulnerable System: H=High (total loss), L=Low (partial), N=None",
      ),
    VI: z
      .enum(["H", "L", "N"])
      .describe(
        "Integrity Impact on Vulnerable System: H=High (total loss), L=Low (partial), N=None",
      ),
    VA: z
      .enum(["H", "L", "N"])
      .describe(
        "Availability Impact on Vulnerable System: H=High (total loss), L=Low (partial), N=None",
      ),

    // Base Metrics - Subsequent System Impact
    SC: z
      .enum(["H", "L", "N"])
      .describe(
        "Confidentiality Impact on Subsequent Systems: H=High, L=Low, N=None (no pivoting)",
      ),
    SI: z
      .enum(["H", "L", "N"])
      .describe(
        "Integrity Impact on Subsequent Systems: H=High, L=Low, N=None",
      ),
    SA: z
      .enum(["H", "L", "N"])
      .describe(
        "Availability Impact on Subsequent Systems: H=High, L=Low, N=None",
      ),

    // Threat Metric
    E: z
      .enum(["A", "P", "U"])
      .describe(
        "Exploit Maturity: A=Attacked (working exploit exists), P=POC available, U=Unreported",
      ),
  }),
  reasoning: z
    .string()
    .describe(
      "Brief explanation (2-3 sentences) of the key factors that influenced the metric choices",
    ),
  cwes: z
    .array(CweEntrySchema)
    .describe(
      "CWE classifications for this vulnerability, most specific first",
    ),
});

// =============================================================================
// System Prompt
// =============================================================================

const CVSS_SCORER_SYSTEM_PROMPT = `You are a CVSS 4.0 scoring specialist. Your task is to analyze vulnerability findings and determine the appropriate CVSS 4.0 Base metrics.

## CVSS 4.0 Metrics Guide

### Attack Vector (AV)
- **N (Network)**: Remotely exploitable over the internet (web app vulns, network services)
- **A (Adjacent)**: Requires shared physical or logical network (same WiFi, VLAN)
- **L (Local)**: Requires local access or user interaction to deliver payload
- **P (Physical)**: Requires physical hardware access

### Attack Complexity (AC)
- **L (Low)**: No special preparation needed, works reliably
- **H (High)**: Requires race conditions, bypassing defenses, or specific configurations

### Attack Requirements (AT)
- **N (None)**: Works under normal conditions
- **P (Present)**: Requires specific deployment conditions (race window, man-in-the-middle position)

### Privileges Required (PR)
- **N (None)**: Unauthenticated attack
- **L (Low)**: Requires basic user-level privileges
- **H (High)**: Requires administrative/root privileges

### User Interaction (UI)
- **N (None)**: No user action required
- **P (Passive)**: User visits a page, opens a file, or is on a vulnerable session
- **A (Active)**: User must click a link, dismiss warnings, or actively interact

### Confidentiality Impact (VC - Vulnerable System, SC - Subsequent Systems)
- **H (High)**: Complete loss of confidentiality (full data access, credential theft)
- **L (Low)**: Limited data exposure (some info leak but not critical)
- **N (None)**: No confidentiality impact

### Integrity Impact (VI - Vulnerable System, SI - Subsequent Systems)
- **H (High)**: Complete loss of integrity (arbitrary modification, code execution)
- **L (Low)**: Limited modification capability
- **N (None)**: No integrity impact

### Availability Impact (VA - Vulnerable System, SA - Subsequent Systems)
- **H (High)**: Complete denial of service
- **L (Low)**: Reduced performance or intermittent availability
- **N (None)**: No availability impact

### Exploit Maturity (E)
- **A (Attacked)**: Working exploit exists (POC confirmed vulnerability)
- **P (POC)**: Proof-of-concept code exists but may not be weaponized
- **U (Unreported)**: No known public exploit

## Vulnerability Class Guidelines

### SQL Injection (sqli)
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC:H (data access), VI:H (data modification), VA:L-H (depending on impact)
- SC/SI/SA: Usually N unless database is shared

### Cross-Site Scripting (xss)
- Reflected: AV:N, AC:L, AT:N, PR:N, UI:A (user must click)
- Stored: AV:N, AC:L, AT:N, PR varies, UI:P (user visits page)
- VC:L (session theft), VI:L (DOM modification), VA:N
- SC/SI/SA: Usually N (client-side only)

### Command Injection / RCE
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC:H, VI:H, VA:H (complete system compromise)
- SC/SI/SA: Potentially H if can pivot

### IDOR / Access Control
- Typically: AV:N, AC:L, AT:N, PR:L (needs some access), UI:N
- Impact varies based on what data is accessed
- If PR=N (no authentication required), this is NOT IDOR. Reclassify as 'missing-authentication'.

### SSRF
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC on vulnerable: L-N, SC on subsequent: H (internal network access)

### Path Traversal / LFI
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC:H (file read), VI:N (unless write), VA:N

### Information Disclosure (exposed secrets, JS bundle leaks, API spec exposure, sensitive data exposure)
- **VC:L** when only metadata/structure is exposed (API routes, merchant IDs, config, version info)
- **VC:H** when credentials, PII, auth tokens, or API secrets are exposed
- **E:A** only when the disclosed info was actually used in further exploitation during this test
- **E:P** when it aids reconnaissance but wasn't weaponized in this engagement
- For public keys (pk_*, publishable keys): not typically a vulnerability unless context suggests otherwise
- Severity range: LOW-MEDIUM for metadata, MEDIUM-HIGH for credentials/PII

### Missing Rate Limiting
- Typically: **AV:N, AC:L, AT:P** (brute-force requires time within validity window)
- **VC/VI** depends on what the brute-force enables:
  - **VC:H, VI:H** if account takeover is feasible (short OTP + no expiry, weak passwords)
  - **VC:L, VI:N** if only enumeration is enabled
- **E:P** unless actual brute-force succeeded during testing, then **E:A**
- **Do NOT score based on theoretical full exploit chain** if only the rate limit gap was demonstrated
- Severity range: typically LOW-MEDIUM unless demonstrated takeover elevates to HIGH

### Missing Security Headers (clickjacking, CSP, X-Frame-Options, HSTS, etc.)
- **UI:A** (requires user to visit attacker-controlled page AND interact)
- **VC:N, VI:L** (limited actions via clickjacking), **VA:N**
- **E:U** unless an actual clickjacking/framing attack was demonstrated, then **E:P**
- These are typically **LOW severity** (CVSS < 4.0)
- Only elevate if concrete attack scenario was demonstrated

### User Enumeration
- **VC:L** (limited info: email existence, username validity, account type)
- **VI:N, VA:N, SC:N, SI:N, SA:N**
- Typically **LOW-MEDIUM** severity range (CVSS 3.0-5.0)
- **Do NOT inflate to HIGH** based on theoretical downstream attacks (brute-force, phishing)
- Score what was demonstrated, not what could theoretically follow

### Hardcoded Credentials / API Keys
- Distinguish key types carefully:
  - **Public keys** (pk_*, publishable API keys): informational, **not typically a vulnerability**
  - **Secret keys** (sk_*, API secrets, passwords) in client code: **VC:H, VI:H**
  - **Service keys** with billing impact (unrestricted Google Maps API key): **VA:L, VC:N**
- **E:A** only if the key was used to access unauthorized resources during testing
- **E:P** if the key is valid but wasn't exploited in this engagement
- Severity: **INFORMATIONAL** for public keys, **HIGH-CRITICAL** for secret keys with access, **MEDIUM** for billing-only impact

### Captcha Bypass
- Typically: **AV:N, AC:L, AT:N, PR:N, UI:N**
- **VI:L** (can create unauthorized accounts), **VA:L** (resource exhaustion potential)
- **VC:N** (no data exposed by bypassing captcha alone)
- In **sandbox/staging environments**, consider **AT:P** if captcha may be intentionally disabled
- Severity range: typically **LOW-MEDIUM** unless chained with other impacts

### Authentication Bypass (OTP bypass, default credentials, session fixation)
- **VC:H** (full account access), **VI:L-H** (depends on account capabilities)
- If **sandbox-only** and may be intentional (test credentials, debug mode): note in reasoning, consider **E:P** not **E:A**
- If production-like or confirmed unintentional: **E:A**
- Severity: typically **HIGH-CRITICAL** for real bypasses, **MEDIUM** for intentional test credentials in sandbox

### Denial of Service / Resource Exhaustion (unbounded input, algorithmic complexity, amplification)
- Typically: **AV:N, AC:L, AT:N, PR** varies (often **L** for authenticated endpoints), **UI:N**
- **VC:N, VI:N** — DoS has no confidentiality/integrity impact unless separately demonstrated
- **VA** must reflect what the evidence actually proves, not the worst case it implies:
  - **VA:L** when a single request degrades performance or ties up one worker temporarily (the typical demonstrated case). A slow response (e.g. several seconds) for one request is **VA:L**, not **VA:H**.
  - **VA:H** ONLY when the POC demonstrates a *sustained, service-wide* outage — e.g. proven worker-pool exhaustion at realistic concurrency, or the service staying unavailable to other users. Extrapolating "5-10 concurrent requests would exhaust the pool" is theoretical and does NOT justify **VA:H** unless the POC actually showed it.
- **E:P** when only the resource-consumption gap was demonstrated; **E:A** only if an actual outage was produced and observed during testing.
- Severity range: typically **LOW-MEDIUM**. Reserve **HIGH** for a demonstrated full outage with no easy mitigation.

### OAuth Flow Weaknesses (missing PKCE, weak/predictable state, state integrity)
- These findings describe a *missing or weak control* in an auth flow. The impact (account/session takeover) is only realizable when chained with a *separate* capability: an authorization-code interception path (open redirect, referrer leakage, network MITM) or a forgeable/guessable state.
- **Do NOT credit full VC:H/VI:H on the vulnerable system unless the interception/forgery chain was actually demonstrated end to end.** If only the absence of PKCE (or a missing signature) was shown, the direct impact on the vulnerable system is limited → prefer **VC:L/VI:L or N** and **E:P**, with **AC:H** and/or **AT:P** to reflect the required preconditions.
- If a state parameter already binds to the initiating user (e.g. a server-side userId check on return), missing PKCE/signing is largely a **defense-in-depth / best-practice** gap → **LOW** (or informational when state is also unguessable and validated).
- Severity range: typically **LOW** for "missing PKCE / unsigned state" in isolation; elevate only when a working interception or CSRF-via-state-forgery chain is demonstrated.

## Severity Calibration Principles

Apply these across every vulnerability class. They override the worst-case instinct.

- **Score what was demonstrated, not what could theoretically follow.** The CVSS reflects the impact the POC actually proved on the target, not the maximal impact the weakness might enable in a different configuration or when chained with an undiscovered bug.
- **Chained / conditional exploitation:** when realizing impact depends on a *separate, undemonstrated* vulnerability or attacker-favorable precondition (interception position, a second bug, a guessed identifier), reflect that in the exploitability metrics (**AC:H**, **AT:P**, exploit maturity **E:P/U**) and do NOT assign full **VC:H/VI:H/VA:H** to the vulnerable system. A finding whose impact is entirely contingent on a missing precondition trends **LOW**.
- **Security-boundary bypass without proven sensitive exposure:** when a test shows an access-control/authorization boundary was bypassed but the data actually returned is non-sensitive or same-tenant/expected-visible, score the *demonstrated* confidentiality impact (often **VC:L** or **VC:N**), not the boundary's theoretical worst case. Note explicitly in the reasoning what data was (and was not) exposed.
- **Cross-tenant vs same-tenant matters:** confirmed cross-tenant/cross-user exposure of private data justifies **VC:H**; same-tenant data the identity could plausibly already see does not. If tenancy is unproven, say so and score conservatively.

## Analysis Instructions

1. Read the finding description and evidence carefully
2. Consider the attack vector based on how the vulnerability was exploited
3. Assess complexity based on whether special conditions were needed
4. Determine privileges based on authentication requirements
5. Evaluate user interaction based on exploit mechanics
6. Assess impact on both the vulnerable system AND potential subsequent systems — score what the evidence proves, not the worst case it implies (see Severity Calibration Principles)
7. Exploit Maturity (E): use **A (Attacked)** only when the POC demonstrated the actual security impact (data accessed, outage produced, session taken over). When the POC only proved the *gap* exists — a missing control, a slow response, a boundary bypass without confirmed sensitive exposure — use **P (POC)**. Do not default to **A** merely because a script ran and exited 0.

Always provide brief reasoning explaining your key decisions.

## CWE Assignment Guidelines

In addition to CVSS metrics, assign one or more CWE identifiers to the finding. For each CWE, provide a brief reasoning explaining why it applies.

### Common CWE Mappings

| Vulnerability Class | Primary CWE | Related CWEs |
|---------------------|------------|--------------|
| SQL Injection | CWE-89 | CWE-564 (Hibernate), CWE-943 (NoSQL) |
| Cross-Site Scripting (XSS) | CWE-79 | CWE-80 (Basic XSS), CWE-87 (Alt XSS) |
| Command/OS Injection | CWE-78 | CWE-77 (Command Injection) |
| Code Injection / RCE | CWE-94 | CWE-95 (Eval Injection), CWE-96 (Static Code Injection) |
| IDOR / Access Control | CWE-639 | CWE-284 (Improper Access Control), CWE-862 (Missing AuthZ) |
| SSRF | CWE-918 | — |
| Path Traversal / LFI | CWE-22 | CWE-23 (Relative Path), CWE-36 (Absolute Path) |
| XXE | CWE-611 | CWE-776 (Recursive Entity) |
| SSTI | CWE-1336 | CWE-94 (Code Injection) |
| CSRF | CWE-352 | — |
| Deserialization | CWE-502 | — |
| Open Redirect | CWE-601 | — |
| Information Disclosure | CWE-200 | CWE-209 (Error Messages), CWE-532 (Log Files), CWE-538 (File/Path Info) |
| Authentication Bypass | CWE-287 | CWE-306 (Missing Auth), CWE-798 (Hardcoded Credentials) |
| Cryptographic Issues | CWE-327 | CWE-328 (Weak Hash), CWE-330 (Insufficient Randomness) |
| Missing Rate Limiting | CWE-307 | CWE-799 (Improper Input Validation - brute-force) |
| User Enumeration | CWE-203 | CWE-204 (Observable Response Discrepancy) |
| Hardcoded Credentials | CWE-798 | CWE-259 (Hard-coded Password), CWE-321 (Hard-coded Crypto Key) |
| Captcha Bypass | CWE-804 | CWE-837 (Improper Enforcement of Single Access) |
| Missing Security Headers | CWE-1021 | CWE-693 (Protection Mechanism Failure), CWE-16 (Configuration) |
| Denial of Service / Resource Exhaustion | CWE-400 | CWE-770 (Allocation Without Limits), CWE-1333 (Inefficient Regex) |
| OAuth Flow Weakness (missing PKCE, weak state) | CWE-352 | CWE-345 (Insufficient Verification of Authenticity), CWE-1275 (Sensitive Cookie Weak Attributes) |

### CWE Assignment Rules

1. Assign the **most specific applicable CWE(s)** — prefer CWE-89 (SQL Injection) over CWE-74 (generic Injection).
2. Use the standard \`CWE-<number>\` format (e.g., CWE-89, not "CWE 89" or "89").
3. Assign **1-3 CWEs** per finding. Multiple CWEs are appropriate when the vulnerability spans categories (e.g., an IDOR that also leaks PII: CWE-639 + CWE-200).
4. Order CWEs by relevance — the primary weakness first.
5. When the vulnerability class is provided, use it as a strong hint but verify against the evidence.
6. For each CWE, provide a specific reasoning explaining why it applies to *this* finding — not a generic definition of the CWE.`;

// =============================================================================
// Main Function
// =============================================================================

/**
 * Score a vulnerability finding with CVSS 4.0
 *
 * @param input - The finding data and conversation context
 * @param model - The AI model to use for scoring
 * @returns The CVSS 4.0 score with reasoning
 */
export async function scoreFindingWithCVSS(
  input: CVSSScorerInput,
  model: AIModel,
  authConfig?: AIAuthConfig,
  abortSignal?: AbortSignal,
): Promise<CVSSScorerResult> {
  const prompt = buildScoringPrompt(input);

  // Generate structured CVSS metrics using AI
  const assessment = await generateObjectResponse({
    model,
    schema: CVSSMetricsOutputSchema,
    prompt,
    system: CVSS_SCORER_SYSTEM_PROMPT,
    authConfig,
    abortSignal,
  });

  // Calculate final score using the CVSS calculator
  const cvssResult = calculateCVSS4Score({
    ...assessment.metrics,
  });

  // Validate CWE IDs against the canonical MITRE database.
  // Unknown/hallucinated IDs are silently dropped.
  const { validated: validatedCwes } = validateCweEntries(assessment.cwes);

  return {
    score: cvssResult.score,
    severity: cvssResult.severity,
    vectorString: cvssResult.vectorString,
    metrics: cvssResult.metrics,
    scoreType: cvssResult.scoreType,
    reasoning: assessment.reasoning,
    cwes: validatedCwes,
  };
}

/**
 * Build the scoring prompt from finding data and context
 */
const MAX_EVIDENCE_CHARS = 10_000;
const MAX_DESCRIPTION_CHARS = 3_000;
const MAX_IMPACT_CHARS = 2_000;

function truncateField(value: string, limit: number): string {
  if (value.length <= limit) return value;
  return `${value.substring(0, limit)}\n... [truncated]`;
}

function buildScoringPrompt(input: CVSSScorerInput): string {
  const { finding, agentMessages } = input;

  const description = truncateField(finding.description, MAX_DESCRIPTION_CHARS);
  const impact = truncateField(finding.impact, MAX_IMPACT_CHARS);
  const evidence = truncateField(finding.evidence, MAX_EVIDENCE_CHARS);

  let prompt = `# Vulnerability Finding to Score

## Finding Details

**Title:** ${finding.title}
**Vulnerability Class:** ${finding.vulnerabilityClass || "Unknown"}
**Endpoint:** ${finding.endpoint}

### Description
${description}

### Impact Assessment
${impact}

### Evidence (POC Output)
\`\`\`
${evidence}
\`\`\`

`;

  // Add context from agent conversation if available
  if (agentMessages && agentMessages.length > 0) {
    prompt += `## Discovery Context

The following is a summary of how this vulnerability was discovered (from the testing agent's conversation):

`;
    // Extract relevant context from messages
    const contextSummary = extractContextSummary(agentMessages);
    prompt += contextSummary;
  }

  prompt += `
## Task

Analyze this vulnerability finding and determine the appropriate CVSS 4.0 metrics.

Consider:
1. How the vulnerability is exploited (attack vector, complexity, requirements)
2. What privileges/authentication were needed
3. Whether user interaction is required
4. The actual impact demonstrated in the evidence
5. Potential for lateral movement or subsequent system compromise

Provide your metrics assessment and brief reasoning.
`;

  return prompt;
}

/**
 * Extract relevant context from agent conversation messages
 */
function extractContextSummary(messages: Record<string, unknown>[]): string {
  const contextParts: string[] = [];
  let foundToolCalls = 0;
  const maxToolCalls = 5; // Limit context size

  for (const message of messages) {
    if (foundToolCalls >= maxToolCalls) break;

    // Extract assistant reasoning
    if (message.role === "assistant" && typeof message.content === "string") {
      // Look for hypothesis/validation blocks
      const hypothesisMatch = message.content.match(
        /HYPOTHESIS:[\s\S]*?(?=VALIDATION:|$)/,
      );
      const validationMatch = message.content.match(
        /VALIDATION:[\s\S]*?(?=HYPOTHESIS:|$)/,
      );

      if (hypothesisMatch) {
        contextParts.push(`- ${hypothesisMatch[0].substring(0, 300)}...`);
      }
      if (validationMatch) {
        contextParts.push(`- ${validationMatch[0].substring(0, 300)}...`);
      }
    }

    // Extract tool call descriptions
    if (message.role === "assistant" && Array.isArray(message.content)) {
      for (const rawPart of message.content) {
        const part = rawPart as Record<string, unknown>;
        if (part.type === "tool-call" && part.toolName) {
          const input = part.input as Record<string, unknown> | undefined;
          const desc = input?.toolCallDescription || `Used ${part.toolName}`;
          contextParts.push(`- Tool: ${String(desc)}`);
          foundToolCalls++;
        }
      }
    }
  }

  if (contextParts.length === 0) {
    return "No additional context available from testing conversation.\n";
  }

  return `${contextParts.join("\n")}\n`;
}

// =============================================================================
// Default Model
// =============================================================================

/** Default model for CVSS scoring (fast and cost-effective) */
const DEFAULT_CVSS_MODEL: AIModel = "claude-4-5-haiku";
