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

const SYSTEM_PROMPT = `You are an expert application security engineer evaluating the quality of a single attack path from a threat model. Be rigorous — most attack paths have room for improvement.

Score each criterion from 1 to 5. Use the FULL range. A score of 3 should be common for decent work, 4 for genuinely strong work, and 5 only for exceptional quality.

## Scoring Scale with Examples

**Specificity** — Does this path reference real code/endpoints/config?
- 1: Generic ("the application may be vulnerable to XSS")
- 2: Names a feature area but no code ("the login page could have injection")
- 3: Names specific endpoints or routes ("POST /api/auth/login is vulnerable")
- 4: References specific files AND endpoints ("src/routes/auth.ts line 42 constructs SQL via string concatenation")
- 5: References files, line numbers, variable names, and traces the data flow through code

**Mechanism Quality** — Are steps concrete and followable?
- 1: Single vague step ("exploit the vulnerability")
- 2: 3-4 high-level steps without technical detail
- 3: 8+ steps but some are generic ("the attacker gains access")
- 4: 8+ steps with specific technical actions at each stage
- 5: 8+ steps where each step names the exact request, parameter, or code path involved

**Severity Calibration** — Is the assigned severity defensible?
- 1: Severity is clearly wrong (info disclosure rated Critical)
- 3: Severity is reasonable but not well-justified
- 5: Severity matches impact description with clear reasoning

**Pentest Guidance** — Could a pentester start testing immediately?
- 1: No guidance or "test for vulnerabilities"
- 2: Names a vulnerability class to test for
- 3: Suggests specific tools or approaches ("use sqlmap", "test with Burp")
- 4: Includes specific payloads, parameters, or test commands
- 5: Provides ready-to-run commands with exact endpoints, headers, and expected responses

**Impact Concreteness** — What specifically happens if exploited?
- 1: "Data breach" or "security impact"
- 3: Names the type of data or access ("user credentials are exposed")
- 5: Names exact tables, fields, or operations ("attacker reads users.email, users.password_hash for all rows")

**Control Analysis** — Are controls and gaps correctly assessed?
- 1: No controls mentioned
- 3: Names relevant controls but assessment is surface-level
- 5: Correctly identifies control IDs, assesses their effectiveness, and identifies specific bypass conditions

## Hard Rules
- If the attack path contains NO file paths or line numbers, Specificity CANNOT exceed 3.
- If pentest guidance contains NO concrete payloads or commands, Pentest Guidance CANNOT exceed 3.
- If impact uses only generic terms ("data breach", "unauthorized access") without specifics, Impact Concreteness CANNOT exceed 2.

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
