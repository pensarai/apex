/**
 * Finding Judge
 *
 * A specialized validation module that analyzes POC scripts and their output
 * to determine whether a claimed vulnerability is legitimately demonstrated.
 *
 * Spawned by the document_vulnerability tool after POC execution succeeds
 * to catch hallucinated findings, hardcoded fake evidence, and mismatched
 * severity claims before they are persisted.
 */

import { z } from "zod";
import { generateObjectResponse, type AIModel } from "../../../ai";
import { type AIAuthConfig } from "../../../ai/utils";

// =============================================================================
// Types
// =============================================================================

export const FINDING_TYPES = [
  "vulnerability",
  "informational",
  "expected-behavior",
] as const;
export type FindingType = (typeof FINDING_TYPES)[number];

export interface FindingJudgeInput {
  /** The full POC script content */
  pocScript: string;
  /** Script language */
  pocType: "bash" | "python" | "javascript";
  /** POC execution output */
  pocOutput: {
    stdout: string;
    stderr: string;
    exitCode: number;
  };
  /** The vulnerability claim to validate against */
  claim: {
    title: string;
    description: string;
    impact: string;
    evidence: string;
    endpoint: string;
    vulnerabilityClass?: string;
  };
}

export interface FindingJudgeResult {
  /** Whether the finding is legitimate and well-demonstrated */
  valid: boolean;
  /** Classification of the finding */
  findingType: FindingType;
  /** Confidence in the judgment (0.0-1.0) */
  confidence: number;
  /** Explanation of the judgment */
  reasoning: string;
  /** Specific concerns identified (empty if valid) */
  concerns: string[];
  /** Present when the judge fell back due to an error — contains diagnostics */
  error?: {
    message: string;
    type: string;
    model: string;
    stack?: string;
  };
}

// =============================================================================
// Schema for AI Output
// =============================================================================

const FindingJudgeOutputSchema = z.object({
  valid: z
    .boolean()
    .describe(
      "Whether the POC legitimately demonstrates the claimed vulnerability",
    ),
  findingType: z
    .enum(FINDING_TYPES)
    .describe(
      "Classification: 'vulnerability' for genuine security issues, 'informational' for low-risk observations worth noting, 'expected-behavior' for findings that describe intentional design decisions",
    ),
  confidence: z
    .number()
    .describe(
      "Confidence in the judgment, a decimal between 0.0 (no confidence) and 1.0 (certain)",
    ),
  reasoning: z
    .string()
    .describe(
      "Brief explanation (2-4 sentences) of the key factors that led to this judgment",
    ),
  concerns: z
    .array(z.string())
    .describe(
      "Specific concerns identified. Empty array if the finding is valid.",
    ),
});

// =============================================================================
// System Prompt
// =============================================================================

const FINDING_JUDGE_SYSTEM_PROMPT = `You are a security finding validation specialist. Your task is to analyze a proof-of-concept (POC) script and its execution output to determine whether it legitimately demonstrates the claimed vulnerability.

## Your Role

You are the last line of defense against false positives, hallucinated findings, and fabricated evidence in an automated penetration testing pipeline. Your judgment determines whether a finding gets documented and reported to a client. Be thorough but fair — reject only when you have specific, articulable concerns.

## Evaluation Criteria

### 1. Correctness
Does the POC output actually demonstrate the claimed vulnerability?

- For SQL injection: Does the output show data that should not be accessible, error messages revealing query structure, or behavioral differences indicating injection success?
- For XSS: Does the output show the payload reflected/executed in a response context where it would run in a browser?
- For command injection / RCE: Does the output show execution of commands on the target system (not the local testing machine)?
- For SSRF: Does the output show responses from internal services that should not be externally accessible?
- For path traversal: Does the output show file contents from outside the intended directory?
- For IDOR: Does the output show access to resources belonging to other users/accounts?
- For authentication bypass: Does the output show access to protected resources without valid credentials?
- For email injection / HTML injection: The PoC must show more than "server accepted HTML input." Verify: (a) the email was actually sent (success response confirming delivery), AND (b) ideally, the email was retrieved via IMAP/POP3 or confirmed via out-of-band callback. If only (a) is met, reduce confidence and note "HTML rendering in email client was not independently verified."
- For missing rate limiting / anti-automation: Does the output show a statistically significant number of requests (minimum 50) that all succeeded without throttling? A handful of successful requests (fewer than 20) is insufficient — rate limiting may use sliding windows, IP-based quotas, or progressive delays that only trigger at higher volumes. The finding should document the exact request count and distribution.

### 2. Hallucination Detection
Could the POC be manufacturing fake evidence rather than demonstrating real exploitation?

Red flags:
- Script uses \`echo\`, \`print\`, \`console.log\` to output "evidence" that was never received from the target
- Script constructs fake HTTP responses or error messages
- Output appears before any network request is made to the target
- Script hardcodes "expected" output and prints it regardless of actual response
- Evidence text does not match what the target endpoint would plausibly return

### 3. Hardcoded / Brute-Force Check
Does the POC contain static values that fake exploitation success?

Red flags:
- Script contains hardcoded flags, tokens, or secrets that it "discovers"
- Script uses string matching against a hardcoded expected response to determine success
- Script always exits 0 regardless of the actual HTTP response status or content
- Success determination is based on the presence of a string the script itself injected into its own variables
- Script ignores the actual response body and declares success based solely on HTTP status code when the vulnerability requires response analysis

### 4. Severity Alignment
Does the demonstrated impact match the claimed vulnerability and impact?

- A POC that only shows an error message should not claim "full database compromise"
- A reflected XSS POC should not claim "remote code execution"
- Information disclosure evidence should not be described as a critical RCE
- The endpoint tested should match the endpoint claimed in the finding

### 5. Design Intent / Expected Behavior
Is the "vulnerability" actually expected behavior for this context?

Red flags for expected behavior (classify as expected-behavior or informational, not vulnerability):
- Public API keys designed for client-side use (Stripe publishable keys \`pk_*\`, Google Maps API keys, Firebase config, reCAPTCHA site keys)
- Sandbox/demo environments with intentionally relaxed security controls (disabled captcha, test credentials, test OTP codes)
- Checkout/payment widgets accepting postMessages from any origin (required for cross-origin merchant embedding)
- CORS configurations that are permissive by design for public APIs
- Features working exactly as documented by the application
- Security headers missing on endpoints serving only static/public content

Ask: "Would a knowledgeable developer of this application consider this a bug, or an intentional design choice?"

## Decision Framework

- **ACCEPT as vulnerability** when: The POC makes a real request to the target, receives a response containing genuine evidence of the vulnerability, the evidence matches the claim, and the behavior is clearly unintentional or exploitable beyond the application's designed functionality.
- **ACCEPT as informational** when: The finding describes a real observation but is low-risk, describes a common default configuration, or could be intentional. Examples: missing security headers on non-sensitive endpoints, verbose error messages, permissive CORS on a public API.
- **ACCEPT as expected-behavior** when: The finding describes behavior that is clearly by design. Examples: public API keys intended for client-side use, checkout widgets accepting cross-origin postMessages, sandbox environments with relaxed security.
- **REJECT** when: The POC fabricates evidence, the output does not demonstrate the claimed vulnerability, the success condition is hardcoded, or there is a fundamental mismatch between what was demonstrated and what was claimed.

### Confidence calibration
- When in doubt about exploitation legitimacy, **ACCEPT as vulnerability** — a borderline-real finding is worth documenting.
- When in doubt about whether behavior is by-design, **classify as informational** rather than vulnerability — documenting expected behavior as a vulnerability undermines report credibility.
- Email/HTML injection findings without independent rendering verification (e.g., only a 200 OK response): confidence must be < 0.7. Add a concern noting that HTML rendering in the recipient's email client was not independently verified.
- Below 0.7 confidence: always populate the concerns array explaining what makes the finding marginal.
- For rate-limiting / anti-automation findings: If the POC sent fewer than 50 requests, assign confidence below 0.7 and add a concern: "Insufficient test volume — only N requests were sent. Rate limiting mechanisms may use thresholds above this volume." If the finding does not state the exact number of requests sent, add a concern: "Finding does not specify the number of test requests sent."

## Output Instructions

Provide your judgment as a structured assessment:
- \`valid\`: true if the finding should be accepted (as vulnerability, informational, or expected-behavior), false if it should be rejected
- \`findingType\`: "vulnerability" for genuine security issues, "informational" for low-risk observations, "expected-behavior" for intentional design decisions
- \`confidence\`: your confidence level from 0.0 to 1.0
- \`reasoning\`: 2-4 sentences explaining your key observations
- \`concerns\`: specific issues found (empty array if valid). Each concern should be a single actionable sentence.`;

// =============================================================================
// Main Function
// =============================================================================

const MAX_POC_SCRIPT_CHARS = 8_000;
const MAX_OUTPUT_CHARS = 10_000;
const MAX_EVIDENCE_CHARS = 5_000;
const MAX_DESCRIPTION_CHARS = 3_000;

function truncate(value: string, limit: number): string {
  if (value.length <= limit) return value;
  return value.substring(0, limit) + "\n... [truncated]";
}

/**
 * Validate a vulnerability finding by analyzing its POC script and output.
 *
 * @param input - The POC script, output, and claimed vulnerability details
 * @param model - The AI model to use for judgment
 * @returns Structured judgment with validity, confidence, reasoning, and concerns
 */
export async function judgeFinding(
  input: FindingJudgeInput,
  model: AIModel,
  authConfig?: AIAuthConfig,
  abortSignal?: AbortSignal,
): Promise<FindingJudgeResult> {
  const modelStr = String(model ?? "undefined");

  try {
    const prompt = buildJudgingPrompt(input);

    const result = await generateObjectResponse({
      model,
      schema: FindingJudgeOutputSchema,
      prompt,
      system: FINDING_JUDGE_SYSTEM_PROMPT,
      authConfig,
      abortSignal,
    });

    return result;
  } catch (err: unknown) {
    const errObj =
      typeof err === "object" && err !== null
        ? (err as Record<string, unknown>)
        : {};
    const message = err instanceof Error ? err.message : String(err);
    const type = err instanceof Error ? err.constructor.name : typeof err;
    const stack = err instanceof Error ? err.stack : undefined;
    // Surface status code from API errors (e.g. 429 rate limit, 401 auth)
    const statusCode = errObj.status ?? errObj.statusCode ?? errObj.code;
    const statusStr = statusCode != null ? ` [status=${statusCode}]` : "";

    const hasAuth = authConfig != null;
    const authKeys =
      hasAuth && typeof authConfig === "object"
        ? Object.keys(authConfig as Record<string, unknown>).join(",")
        : "none";

    console.error(
      `[FindingJudge] Validation failed: model=${modelStr} type=${type}${statusStr} authConfigKeys=${authKeys} message=${message}`,
    );

    return {
      valid: true,
      findingType: "vulnerability",
      confidence: 0.5,
      reasoning: `Finding judge failed (${type}${statusStr}: ${message.substring(0, 200)}), accepting with low confidence.`,
      concerns: [],
      error: {
        message: `${message}${statusStr}`,
        type,
        model: modelStr,
        stack: stack?.substring(0, 500),
      },
    };
  }
}

// =============================================================================
// Prompt Builder
// =============================================================================

function buildJudgingPrompt(input: FindingJudgeInput): string {
  const { pocScript, pocType, pocOutput, claim } = input;

  return `# Finding Validation Request

## Claimed Vulnerability

**Title:** ${claim.title}
**Vulnerability Class:** ${claim.vulnerabilityClass || "Unknown"}
**Endpoint:** ${claim.endpoint}

### Description
${truncate(claim.description, MAX_DESCRIPTION_CHARS)}

### Claimed Impact
${truncate(claim.impact, MAX_DESCRIPTION_CHARS)}

### Evidence Provided by Agent
\`\`\`
${truncate(claim.evidence, MAX_EVIDENCE_CHARS)}
\`\`\`

## POC Script (${pocType})

\`\`\`${pocType === "javascript" ? "js" : pocType === "python" ? "python" : "bash"}
${truncate(pocScript, MAX_POC_SCRIPT_CHARS)}
\`\`\`

## POC Execution Output

**Exit Code:** ${pocOutput.exitCode}

### stdout
\`\`\`
${truncate(pocOutput.stdout || "(empty)", MAX_OUTPUT_CHARS)}
\`\`\`

### stderr
\`\`\`
${truncate(pocOutput.stderr || "(empty)", MAX_OUTPUT_CHARS / 2)}
\`\`\`

## Task

Analyze the POC script and its output against the claimed vulnerability. Determine whether this finding is legitimate and should be documented.

Consider:
1. Does the POC actually interact with the target endpoint?
2. Does the output contain genuine evidence of the vulnerability (not fabricated by the script)?
3. Is the success condition based on real exploitation results, not hardcoded values?
4. Does the demonstrated impact align with the claimed vulnerability class and severity?
5. Could the observed behavior be an intentional design decision rather than a vulnerability?
`;
}
