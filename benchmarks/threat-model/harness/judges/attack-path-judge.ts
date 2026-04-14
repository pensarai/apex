/**
 * Threat Model Benchmark — Attack Path Judge
 *
 * Per-path LLM scoring on 6 criteria (1-5 each).
 */

import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { generateObjectResponse } from "../../../../src/core/ai/ai";
import type { AIModel } from "../../../../src/core/ai/ai";
import type { AIAuthConfig } from "../../../../src/core/ai/utils";
import type {
  ParsedAttackPath,
  CanonicalGroundTruth,
  AttackPathJudgeScore,
} from "../types";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const ScoreEntry = z.object({
  score: z.number().describe("Score from 1 to 5"),
  reason: z.string(),
});

const AttackPathScoreSchema = z.object({
  scores: z.object({
    specificity: ScoreEntry,
    mechanismQuality: ScoreEntry,
    severityCalibration: ScoreEntry,
    pentestGuidance: ScoreEntry,
    impactConcreteness: ScoreEntry,
    controlAnalysis: ScoreEntry,
  }),
});

// ---------------------------------------------------------------------------
// Source Context
// ---------------------------------------------------------------------------

function loadSourceContext(
  attackPath: ParsedAttackPath,
  codebasePath: string,
  gt: CanonicalGroundTruth,
): string {
  const maxChars = 16000;
  const parts: string[] = [];

  // Try to find matching vulnerability in ground truth for file references
  const matchingVuln = gt.plantedVulnerabilities.find((v) => {
    const titleWords = attackPath.title.toLowerCase().split(/\s+/);
    const vulnWords = v.name.toLowerCase().split(/\s+/);
    return titleWords.some((tw) => vulnWords.includes(tw));
  });

  // Read vulnerability file if available
  if (matchingVuln?.files.length) {
    for (const f of matchingVuln.files.slice(0, 2)) {
      const fullPath = resolve(codebasePath, f.path);
      if (existsSync(fullPath)) {
        try {
          const content = readFileSync(fullPath, "utf-8");
          const lines = content.split("\n");
          const start = Math.max(0, (f.lineStart ?? 1) - 10);
          const end = Math.min(lines.length, (f.lineEnd ?? start + 50) + 10);
          const snippet = lines.slice(start, end).join("\n");
          parts.push(`### ${f.path} (lines ${start + 1}-${end})\n\`\`\`\n${snippet}\n\`\`\``);
        } catch { /* skip */ }
      }
    }
  }

  // Try to extract file from entry point
  if (parts.length === 0 && attackPath.entryPoint) {
    const fileMatch = attackPath.entryPoint.match(
      /([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})/,
    );
    if (fileMatch) {
      const fullPath = resolve(codebasePath, fileMatch[1]);
      if (existsSync(fullPath)) {
        try {
          const content = readFileSync(fullPath, "utf-8");
          const lines = content.split("\n").slice(0, 200);
          parts.push(`### ${fileMatch[1]}\n\`\`\`\n${lines.join("\n")}\n\`\`\``);
        } catch { /* skip */ }
      }
    }
  }

  const result = parts.join("\n\n");
  return result.slice(0, maxChars) || "(no source context available)";
}

// ---------------------------------------------------------------------------
// Judge
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are an expert application security engineer evaluating the quality of a single attack path from a threat model.

Score each criterion from 1 to 5:
1 = Completely fails the criterion
2 = Major deficiencies
3 = Adequate but with notable gaps
4 = Good with minor issues
5 = Excellent, no meaningful issues

Provide a brief reason for each score.`;

async function judgeOnePath(
  attackPath: ParsedAttackPath,
  codebasePath: string,
  gt: CanonicalGroundTruth,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<{
  pathId: string;
  specificity: number;
  mechanismQuality: number;
  severityCalibration: number;
  pentestGuidance: number;
  impactConcreteness: number;
  controlAnalysis: number;
}> {
  const sourceContext = loadSourceContext(attackPath, codebasePath, gt);

  const prompt = `## Target Application
- Type: ${gt.expectedIdentity.type}
- Domain: ${gt.expectedIdentity.domain}
- Features: ${gt.features.map((f) => f.name).join(", ")}

## Source Code Context
${sourceContext}

## Attack Path Under Evaluation
### ${attackPath.id}: ${attackPath.title} [${attackPath.severity}]
**Attacker Profile:** ${attackPath.attackerProfile}
**Entry Point:** ${attackPath.entryPoint}
**Severity:** ${attackPath.severity}

**Mechanism:**
${attackPath.mechanism.map((s, i) => `${i + 1}. ${s}`).join("\n")}

**Impact:** ${attackPath.impact}

**Existing Controls:** ${attackPath.existingControls.join("; ") || "none listed"}
**Control Gaps:** ${attackPath.controlGaps.join("; ") || "none listed"}
**Pentest Guidance:** ${attackPath.pentestGuidance.slice(0, 1000) || "none provided"}

## Scoring Criteria
1. **Specificity**: Does this path reference real code/endpoints/config? Not a generic template?
2. **Mechanism Quality**: Are the steps concrete, sequential, and followable by a pentester?
3. **Severity Calibration**: Is the assigned severity defensible given the described impact?
4. **Pentest Guidance**: Could a pentester start testing immediately from this guidance?
5. **Impact Concreteness**: Is the impact specific (what data/access) or vague ("data breach")?
6. **Control Analysis**: Are existing controls correctly cited? Are gaps real and actionable?`;

  try {
    const result = await generateObjectResponse({
      model,
      schema: AttackPathScoreSchema,
      prompt,
      system: SYSTEM_PROMPT,
      temperature: 0,
      authConfig,
    });

    if (!result) {
      return defaultPathScore(attackPath.id);
    }

    return {
      pathId: attackPath.id,
      specificity: result.scores.specificity.score,
      mechanismQuality: result.scores.mechanismQuality.score,
      severityCalibration: result.scores.severityCalibration.score,
      pentestGuidance: result.scores.pentestGuidance.score,
      impactConcreteness: result.scores.impactConcreteness.score,
      controlAnalysis: result.scores.controlAnalysis.score,
    };
  } catch (error) {
    console.error(
      `  Attack path judge failed for ${attackPath.id}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return defaultPathScore(attackPath.id);
  }
}

function defaultPathScore(pathId: string) {
  return {
    pathId,
    specificity: 1,
    mechanismQuality: 1,
    severityCalibration: 1,
    pentestGuidance: 1,
    impactConcreteness: 1,
    controlAnalysis: 1,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function judgeAttackPaths(
  attackPaths: ParsedAttackPath[],
  appDir: string,
  gt: CanonicalGroundTruth,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<AttackPathJudgeScore> {
  const codebasePath = resolve(appDir, "src");
  const perPath: AttackPathJudgeScore["perPath"] = [];

  for (const ap of attackPaths) {
    console.log(`    Judging ${ap.id}: ${ap.title.slice(0, 50)}...`);
    const scores = await judgeOnePath(ap, codebasePath, gt, model, authConfig);
    perPath.push(scores);
  }

  // Overall score = average of all criteria across all paths
  const allScores = perPath.flatMap((p) => [
    p.specificity,
    p.mechanismQuality,
    p.severityCalibration,
    p.pentestGuidance,
    p.impactConcreteness,
    p.controlAnalysis,
  ]);
  const score =
    allScores.length > 0
      ? allScores.reduce((a, b) => a + b, 0) / allScores.length
      : 1;

  return { score, perPath };
}
