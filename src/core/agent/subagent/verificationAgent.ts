import { streamResponse, type AIModel } from "../../ai";
import { hasToolCall, tool } from "ai";
import { z } from "zod";
import type { VerificationCriteria } from "./types";
import { VERIFICATION_GUIDANCE } from "./verificationGuidance";

const VERIFICATION_AGENT_PROMPT = `You are a security finding verification specialist. Your job is to independently evaluate whether collected evidence proves a vulnerability exists.

## Your Task

Analyze the provided evidence against the verification criteria and determine:
1. Does the evidence PROVE the vulnerability exists?
2. What specific indicators from the criteria are matched?
3. What evidence is MISSING that would strengthen the finding?
4. What specific techniques should be tried to collect stronger evidence?

## Verification Standards

For a finding to PASS verification:
- HIGH-signal indicators: Must show actual exploitation (data extracted, code executed, access gained)
- MEDIUM-signal indicators: Strong behavioral evidence (timing differences, boolean responses)
- LOW-signal indicators: Detection only (error messages) - NOT sufficient alone

## Evidence Evaluation

Evaluate each piece of evidence:
1. Is it reproducible?
2. Does it prove exploitation or just detection?
3. Could it be a false positive?
4. What would make it conclusive?

## Output

Call complete_verification with your analysis including:
- Whether the finding should pass
- Matched indicators with their signal tier
- Specific gaps in the evidence
- Actionable suggestions for the attack agent

Be STRICT but FAIR. Detection-level evidence (500 errors, SQL syntax errors) indicates a vulnerability EXISTS but doesn't prove EXPLOITATION. Guide the agent on how to achieve exploitation proof.`;

export interface VerificationAgentInput {
  evidence: string;
  confidence: number;
  criteria: VerificationCriteria;
  endpoint: string;
  vulnerabilityClass: string;
  model: AIModel;
  abortSignal?: AbortSignal;
}

export interface VerificationAgentResult {
  passed: boolean;
  verificationQuality: "strong" | "moderate" | "weak" | "failed";
  matchedIndicators: Array<{ indicator: string; tier: string }>;
  gaps: string[];
  suggestions: string[];
  retryGuidance: string;
  reason: string;
}

export async function runVerificationAgent(
  input: VerificationAgentInput
): Promise<VerificationAgentResult> {
  const { evidence, confidence, criteria, endpoint, vulnerabilityClass, model, abortSignal } = input;

  let result: VerificationAgentResult | null = null;

  const VerificationResultSchema = z.object({
    passed: z.boolean().describe("Whether the finding passes verification"),
    verificationQuality: z.enum(["strong", "moderate", "weak", "failed"]).describe("Quality of the verification: strong=high signal match, moderate=medium signal, weak=low signal only, failed=no indicators matched"),
    matchedIndicators: z.array(z.object({
      indicator: z.string().describe("The indicator that was matched"),
      tier: z.enum(["high", "medium", "low"]).describe("Signal tier of the matched indicator"),
    })).describe("Indicators from the criteria that matched the evidence"),
    gaps: z.array(z.string()).describe("What evidence is missing to strengthen the finding"),
    suggestions: z.array(z.string()).describe("Specific techniques the attack agent should try to collect stronger evidence"),
    retryGuidance: z.string().describe("Actionable next steps for the attack agent to retry with stronger evidence"),
    reason: z.string().describe("Explanation of why the verification passed or failed"),
  });

  type VerificationResultInput = z.infer<typeof VerificationResultSchema>;

  const complete_verification = tool({
    description: "Complete verification with your analysis",
    inputSchema: VerificationResultSchema,
    execute: async (params: VerificationResultInput) => {
      result = params;
      return { success: true };
    },
  });

  // Get vulnerability-specific guidance for context
  const vulnGuidance = VERIFICATION_GUIDANCE[vulnerabilityClass] || VERIFICATION_GUIDANCE.generic;

  const userPrompt = `
## Evidence to Verify

${evidence}

## Confidence Level

${confidence}%

## Verification Criteria

**Vulnerability Class:** ${vulnerabilityClass}
**Target Endpoint:** ${endpoint}

**Success Indicators (must match for verification to pass):**
${criteria.successIndicators.map(i =>
  typeof i === 'string'
    ? `- [medium] ${i}`
    : `- [${i.tier}] ${i.indicator}`
).join('\n')}

**Failure Indicators (if matched, finding is invalid):**
${criteria.failureIndicators.map(i => `- ${i}`).join('\n')}

**Minimum Confidence Required:** ${criteria.minimumConfidence}%

## Reference: What Constitutes Strong Evidence for ${vulnerabilityClass}

**HIGH Signal (proves exploitation):**
${vulnGuidance.highSignal.map(i => `- ${i}`).join('\n')}

**MEDIUM Signal (strong evidence):**
${vulnGuidance.mediumSignal.map(i => `- ${i}`).join('\n')}

**LOW Signal (detection only - not sufficient alone):**
${vulnGuidance.lowSignal.map(i => `- ${i}`).join('\n')}

**Key Principles:** ${vulnGuidance.principles.join(' | ')}

## Instructions

Analyze the evidence and call complete_verification with your assessment.

1. Check if any failure indicators are present (automatic fail)
2. Check if confidence meets the minimum threshold
3. Identify which success indicators are matched and their tiers
4. Determine if the evidence proves EXPLOITATION or just DETECTION
5. If verification fails, provide specific, actionable guidance on what techniques to try

Be specific about what's missing and how to get stronger proof. Your suggestions should be concrete techniques the attack agent can execute.
`;

  const streamResult = streamResponse({
    prompt: userPrompt,
    system: VERIFICATION_AGENT_PROMPT,
    model,
    tools: { complete_verification },
    stopWhen: hasToolCall("complete_verification"),
    abortSignal,
    silent: true,
  });

  // Consume the stream
  for await (const chunk of streamResult.fullStream) {
    if (chunk.type === "error") {
      throw (chunk as any).error;
    }
  }

  if (!result) {
    return {
      passed: false,
      verificationQuality: "failed",
      matchedIndicators: [],
      gaps: ["Verification agent did not complete"],
      suggestions: ["Retry verification with the same evidence"],
      retryGuidance: "The verification process failed to complete. Try calling verify_finding again with the same evidence.",
      reason: "Verification agent error - no result returned",
    };
  }

  return result;
}
