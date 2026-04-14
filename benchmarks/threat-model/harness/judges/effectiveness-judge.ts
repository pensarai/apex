/**
 * Threat Model Benchmark — Effectiveness Judge
 *
 * Holistic LLM scoring of the complete threat model (1 call per app).
 * 6 criteria, each scored 1-5.
 */

import { z } from "zod";
import { generateObjectResponse } from "../../../../src/core/ai/ai";
import type { AIModel } from "../../../../src/core/ai/ai";
import type { AIAuthConfig } from "../../../../src/core/ai/utils";
import type { CanonicalGroundTruth, EffectivenessScore } from "../types";

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

const SYSTEM_PROMPT = `You are an expert application security architect evaluating the overall quality of a threat model document.

Score each criterion from 1 to 5:
1 = Completely fails | 2 = Major deficiencies | 3 = Adequate | 4 = Good | 5 = Excellent

Provide a brief reason for each score. Be fair but rigorous.`;

export async function judgeEffectiveness(
  threatModelMd: string,
  gt: CanonicalGroundTruth,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<EffectivenessScore> {
  // Build ground truth summary for the judge
  const gtSummary = `Application: ${gt.expectedIdentity.type} — ${gt.expectedIdentity.domain}
Features (${gt.features.length}): ${gt.features.map((f) => f.name).join(", ")}
Trust Boundaries (${gt.trustBoundaries.length}): ${gt.trustBoundaries.map((tb) => tb.name).join(", ")}
Security Controls (${gt.securityControls.length}): ${gt.securityControls.map((sc) => `${sc.name} (${sc.effectiveness})`).join(", ")}
Planted Vulnerabilities (${gt.plantedVulnerabilities.length}): ${gt.plantedVulnerabilities.map((v) => `${v.name} [${v.severity}]`).join(", ")}`;

  // Truncate the threat model if needed (keep attack paths, trim deployment)
  const truncated =
    threatModelMd.length > 32000
      ? threatModelMd.slice(0, 32000) + "\n\n[...truncated for evaluation...]"
      : threatModelMd;

  const prompt = `## Ground Truth Application Summary
${gtSummary}

## Threat Model Document to Evaluate
${truncated}

## Scoring Criteria
1. **Coverage Breadth**: Does the threat model cover all major feature areas? No important features missed?
2. **Attacker Profile Realism**: Are profiles grounded in the application's domain with diverse skill levels?
3. **Architecture Accuracy**: Does the system architecture section correctly represent the actual application?
4. **Security Posture Assessment**: Does the controls section accurately characterize what's strong, weak, and missing?
5. **Pentest Readiness**: Could a penetration tester use this document as-is to plan an engagement?
6. **Trust Boundary Quality**: Are boundaries application-specific and correctly mapped?`;

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
