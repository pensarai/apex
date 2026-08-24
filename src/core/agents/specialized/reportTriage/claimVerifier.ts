import { z } from "zod";
import {
  type AIAuthConfig,
  type AIModel,
  generateObjectResponse,
} from "../../../ai";
import type {
  BountyReport,
  ClaimVerificationEntry,
  ClaimVerificationResult,
  LiveVerificationResult,
  MaterialClaim,
} from "./types";

const ClaimAssessmentSchema = z.object({
  claims: z.array(
    z.object({
      id: z.string(),
      status: z.enum(["verified", "contradicted", "partial", "untested"]),
      evidence: z.string(),
    }),
  ),
  summary: z.string(),
});

const CLAIM_VERIFIER_SYSTEM = `You are a bug bounty claim verification judge.

Your job is to compare a reporter's material claims against the live-verification evidence. You do not decide final triage. You only classify each listed claim:

- verified: the evidence directly supports the claim.
- contradicted: the evidence directly disproves the claim or shows a materially different behavior.
- partial: the evidence supports a weaker/narrower claim, but not the material claim as written.
- untested: the evidence does not address the claim.

Rules:
- Be evidence-bound. Do not infer facts that are not in the reproduction evidence or observations.
- A global reproduced=true is not enough. Each required claim needs its own supporting evidence.
- For the required security-impact claim, assess whether the evidence demonstrates at least one concrete security impact for the reported vulnerability class. Do not require every downstream consequence in the report's impact paragraph to be proven. Extra downstream impacts belong to optional claims when present.
- If the evidence confirms only a redirect, reflection, or status code and does not show a concrete security boundary impact, mark the required impact claim partial or untested.
- For generic information disclosure or configuration metadata findings (for example stack traces, internal paths, framework versions, public client keys, server/CDN/S3 headers, bucket names, region/account IDs, access key IDs without secret material, signed header lists, source maps, missing HSTS, or verbose errors), mark the required security-impact claim verified only when the live evidence also shows how an attacker can use the disclosure to cause concrete harm. Examples of concrete harm include unauthorized data access, use of a leaked secret/token, account/session impact, auth bypass, protected action execution, exploitable cache poisoning against a normally valid page, or payment/booking/donation impact. If the evidence only proves reconnaissance value or theoretical follow-on risk, mark the required security-impact claim partial.
- If URL parsing, origin validation, authentication state, or attacker capability is only assumed, mark that claim untested.
- If the claimed URL redirects to a final URL where the behavior reproduces, treat the affected-location claim as verified when the original claimed URL is a valid reachable entry point and both hosts are in scope.
- For URLs, apply RFC 3986 parsing precisely: an @ sign only denotes userinfo while it is in the authority component before the first path slash. In https://host/@attacker.example the host is still host and @attacker.example is path content, not a cross-domain redirect.
- Do not treat framework/backend error reachability by itself as a vulnerability. CSRF, authorization bypass, sensitive-data access, mutation execution, and open redirect claims require direct evidence of the claimed attacker-controlled effect.
- Return one assessment for every requested claim id.`;

export function buildMaterialClaims(report: BountyReport): MaterialClaim[] {
  const claims: MaterialClaim[] = [
    {
      id: "vulnerability-class",
      claim: `The behavior is a ${report.vulnerabilityClass} vulnerability.`,
      required: true,
    },
    {
      id: "affected-location",
      claim: `The affected location is ${report.affectedUrl}.`,
      required: true,
    },
    {
      id: "attacker-model",
      claim: `The issue is exploitable by ${report.attackerModel}.`,
      required: true,
    },
    {
      id: "security-impact",
      claim: `Live evidence demonstrates at least one concrete security impact for the reported vulnerability class. The evidence does not need to prove every downstream consequence in the impact section, but it must show how an attacker can use the behavior to cause real harm beyond expected metadata, framework behavior, reconnaissance value, theoretical follow-on risk, or a harmless primitive. For generic information disclosure/configuration metadata, the evidence must actually demonstrate an attack path such as unauthorized data access, secret/token abuse, account/session impact, auth bypass, protected action execution, exploitable cache poisoning against a normally valid page, or payment/booking/donation impact. Claimed impact context: ${report.impact}`,
      required: true,
    },
    {
      id: "claimed-impact-details",
      claim: `The evidence supports the full claimed downstream impact details: ${report.impact}`,
      required: false,
    },
  ];

  if (report.affectedComponent) {
    claims.push({
      id: "affected-component",
      claim: `The affected component is ${report.affectedComponent}.`,
      required: false,
    });
  }

  if (report.pocSteps.length > 0) {
    claims.push({
      id: "poc-steps",
      claim: `The reporter's PoC steps reproduce the issue: ${report.pocSteps.join(" ")}`,
      required: false,
    });
  }

  return claims;
}

export async function verifyReportClaims(opts: {
  report: BountyReport;
  verification: LiveVerificationResult;
  model: AIModel;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
}): Promise<ClaimVerificationResult> {
  const materialClaims = buildMaterialClaims(opts.report);

  try {
    const assessment = await generateObjectResponse({
      model: opts.model,
      schema: ClaimAssessmentSchema,
      system: CLAIM_VERIFIER_SYSTEM,
      prompt: buildClaimVerificationPrompt({
        report: opts.report,
        verification: opts.verification,
        materialClaims,
      }),
      authConfig: opts.authConfig,
      abortSignal: opts.abortSignal,
    });

    return normalizeAssessment(materialClaims, assessment);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      claims: materialClaims.map((claim) => ({
        ...claim,
        status: "untested",
        evidence: `Claim verification judge failed: ${message}`,
      })),
      summary:
        "Claim verification could not complete, so required claims remain untested.",
    };
  }
}

function buildClaimVerificationPrompt(opts: {
  report: BountyReport;
  verification: LiveVerificationResult;
  materialClaims: MaterialClaim[];
}): string {
  return `# Claim Verification Request

## Report
- Title: ${opts.report.title}
- Vulnerability class: ${opts.report.vulnerabilityClass}
- Affected URL: ${opts.report.affectedUrl}
- Affected component: ${opts.report.affectedComponent ?? "(not specified)"}
- Attacker model: ${opts.report.attackerModel}
- Claimed impact: ${opts.report.impact}

## Description
${opts.report.description}

## PoC steps
${opts.report.pocSteps.map((step, index) => `${index + 1}. ${step}`).join("\n") || "(none)"}

## Live verification verdict
- Reproduced: ${opts.verification.reproduced}

### Evidence
\`\`\`
${opts.verification.evidence}
\`\`\`

### Observations
${opts.verification.observations}

## Material claims to verify
${opts.materialClaims
  .map((claim) => `- ${claim.id} (required=${claim.required}): ${claim.claim}`)
  .join("\n")}

Assess each material claim independently.`;
}

function normalizeAssessment(
  materialClaims: MaterialClaim[],
  assessment: z.infer<typeof ClaimAssessmentSchema>,
): ClaimVerificationResult {
  const byId = new Map(assessment.claims.map((claim) => [claim.id, claim]));

  const claims: ClaimVerificationEntry[] = materialClaims.map((claim) => {
    const assessed = byId.get(claim.id);
    if (!assessed) {
      return {
        ...claim,
        status: "untested",
        evidence: "Claim verifier did not return an assessment for this claim.",
      };
    }

    return {
      ...claim,
      status: assessed.status,
      evidence: assessed.evidence,
    };
  });

  return {
    claims,
    summary: assessment.summary,
  };
}
