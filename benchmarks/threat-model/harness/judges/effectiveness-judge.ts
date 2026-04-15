/**
 * Threat Model Benchmark — Effectiveness Judge
 *
 * Holistic LLM scoring of the complete threat model (1 call per app).
 * 6 criteria, each scored 1-5. Receives grounding data to ground the evaluation.
 */

import { z } from "zod";
import { generateObjectResponse } from "../../../../src/core/ai/ai";
import type { AIModel } from "../../../../src/core/ai/ai";
import type { AIAuthConfig } from "../../../../src/core/ai/utils";
import type {
  CanonicalGroundTruth,
  EffectivenessScore,
  GroundingScore,
} from "../types";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const ScoreEntry = z.object({
  score: z.number().describe("Score from 1 to 5"),
  reason: z.string(),
});

const EffectivenessScoreSchema = z.object({
  scores: z.object({
    coverageBreadth: ScoreEntry,
    attackerProfileRealism: ScoreEntry,
    architectureAccuracy: ScoreEntry,
    securityPostureAssessment: ScoreEntry,
    pentestReadiness: ScoreEntry,
    trustBoundaryQuality: ScoreEntry,
  }),
});

// ---------------------------------------------------------------------------
// Judge
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are an expert application security architect evaluating the overall quality of a threat model document. Be rigorous — use the full 1-5 range. A score of 3 is appropriate for solid but unremarkable work. Reserve 5 for genuinely exceptional quality.

Score each criterion from 1 to 5:
1 = Completely fails | 2 = Major deficiencies | 3 = Solid, meets expectations | 4 = Strong, exceeds expectations | 5 = Exceptional, near-perfect

## Hard Rules (MUST be enforced — do not override these)
- If the automated grounding check found <50% of referenced files actually exist, Architecture Accuracy CANNOT exceed 2.
- If fewer than 60% of the application's known features are covered, Coverage Breadth CANNOT exceed 2.
- If attack paths lack specific payloads or test commands, Pentest Readiness CANNOT exceed 3.
- If trust boundaries use textbook names ("External Boundary", "DMZ") rather than application-specific names, Trust Boundary Quality CANNOT exceed 3.
- A score of 5 requires that the document goes BEYOND expectations — not just meets them. Most threat models should score 3-4.

Provide a brief reason for each score.`;

export async function judgeEffectiveness(
  threatModelMd: string,
  gt: CanonicalGroundTruth,
  model: AIModel,
  authConfig?: AIAuthConfig,
  groundingScore?: GroundingScore,
): Promise<EffectivenessScore> {
  // Build ground truth summary for the judge
  const gtSummary = `Application: ${gt.expectedIdentity.type} — ${gt.expectedIdentity.domain}
Features (${gt.features.length}): ${gt.features.map((f) => f.name).join(", ")}
Trust Boundaries (${gt.trustBoundaries.length}): ${gt.trustBoundaries.map((tb) => tb.name).join(", ")}
Security Controls (${gt.securityControls.length}): ${gt.securityControls.map((sc) => `${sc.name} (${sc.effectiveness})`).join(", ")}
Planted Vulnerabilities (${gt.plantedVulnerabilities.length}): ${gt.plantedVulnerabilities.map((v) => `${v.name} [${v.severity}]`).join(", ")}`;

  // Inject objective grounding data so the judge doesn't have to guess
  let groundingInfo = "";
  if (groundingScore) {
    const fc = groundingScore.checks.files_exist;
    const ec = groundingScore.checks.endpoints_exist;
    const cc = groundingScore.checks.config_files_exist;
    groundingInfo = `
## Automated Grounding Verification Results
These are objective, automated checks — not opinions. Factor them into your scoring:
- File references verified: ${fc?.found ?? "?"}/${fc?.total ?? "?"} (${((fc?.score ?? 0) * 100).toFixed(0)}%)
- Endpoint references verified: ${ec?.found ?? "?"}/${ec?.total ?? "?"}  (${((ec?.score ?? 0) * 100).toFixed(0)}%)
- Config file references verified: ${cc?.found ?? "?"}/${cc?.total ?? "?"} (${((cc?.score ?? 0) * 100).toFixed(0)}%)
- Overall grounding score: ${(groundingScore.score * 100).toFixed(0)}%`;
  }

  // Truncate the threat model if needed
  const truncated =
    threatModelMd.length > 32000
      ? threatModelMd.slice(0, 32000) + "\n\n[...truncated for evaluation...]"
      : threatModelMd;

  const prompt = `## Ground Truth Application Summary
${gtSummary}
${groundingInfo}

## Threat Model Document to Evaluate
${truncated}

## Scoring Criteria
1. **Coverage Breadth**: Does the threat model cover all major feature areas? No important features missed?
2. **Attacker Profile Realism**: Are profiles grounded in the application's domain with diverse skill levels?
3. **Architecture Accuracy**: Does the system architecture section correctly represent the actual application? Cross-reference with the grounding verification data above.
4. **Security Posture Assessment**: Does the controls section accurately characterize what's strong, weak, and missing?
5. **Pentest Readiness**: Could a penetration tester use this document as-is to plan an engagement? Are there concrete payloads, commands, or test procedures?
6. **Trust Boundary Quality**: Are boundaries application-specific and correctly mapped? Not generic textbook categories?`;

  try {
    const result = await generateObjectResponse({
      model,
      schema: EffectivenessScoreSchema,
      prompt,
      system: SYSTEM_PROMPT,
      temperature: 0,
      authConfig,
    });

    if (!result) {
      return defaultScore();
    }

    const s = result.scores;

    // Post-process: enforce hard rules using grounding data
    if (groundingScore) {
      const fileScore = groundingScore.checks.files_exist?.score ?? 1;
      if (fileScore < 0.5 && s.architectureAccuracy.score > 2) {
        s.architectureAccuracy.score = 2;
        s.architectureAccuracy.reason += " [CAPPED: <50% file refs verified]";
      }
    }

    const allScores = [
      s.coverageBreadth.score,
      s.attackerProfileRealism.score,
      s.architectureAccuracy.score,
      s.securityPostureAssessment.score,
      s.pentestReadiness.score,
      s.trustBoundaryQuality.score,
    ];
    const score = allScores.reduce((a, b) => a + b, 0) / allScores.length;

    return {
      score,
      coverageBreadth: s.coverageBreadth.score,
      attackerProfileRealism: s.attackerProfileRealism.score,
      architectureAccuracy: s.architectureAccuracy.score,
      securityPostureAssessment: s.securityPostureAssessment.score,
      pentestReadiness: s.pentestReadiness.score,
      trustBoundaryQuality: s.trustBoundaryQuality.score,
    };
  } catch (error) {
    console.error(
      `  Effectiveness judge failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return defaultScore();
  }
}

function defaultScore(): EffectivenessScore {
  return {
    score: 1,
    coverageBreadth: 1,
    attackerProfileRealism: 1,
    architectureAccuracy: 1,
    securityPostureAssessment: 1,
    pentestReadiness: 1,
    trustBoundaryQuality: 1,
  };
}
