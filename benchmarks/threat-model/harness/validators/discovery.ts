/**
 * Threat Model Benchmark — Discovery Validator
 *
 * Computes recall/precision against ground truth using the LLM match classifier.
 */

import type { AIModel } from "../../../../src/core/ai/ai";
import type { AIAuthConfig } from "../../../../src/core/ai/utils";
import type {
  ParsedThreatModel,
  CanonicalGroundTruth,
  DiscoveryScore,
} from "../types";
import { classifyMatches, classifyAdversarial, type MatchItem } from "../judges/match-classifier";

// ---------------------------------------------------------------------------
// Section Extractors
// ---------------------------------------------------------------------------

function extractFeaturesSection(parsed: ParsedThreatModel): string {
  const featureLines = parsed.features
    .map((f) => `${f.name}: ${f.securityRelevance}`)
    .join("\n");
  return featureLines || "(no features section found)";
}

function extractControlsSection(parsed: ParsedThreatModel): string {
  return parsed.securityControls
    .map((sc) => `${sc.id} ${sc.name}: ${sc.type} — ${sc.effectiveness}. ${sc.implementation}. Gaps: ${sc.gaps}`)
    .join("\n") || "(no security controls found)";
}

function extractBoundariesSection(parsed: ParsedThreatModel): string {
  return parsed.trustBoundaries
    .map((tb) => `${tb.name}: ${tb.description}`)
    .join("\n") || "(no trust boundaries found)";
}

function extractAttackPathsSection(parsed: ParsedThreatModel): string {
  return parsed.attackPaths
    .map((ap) =>
      `${ap.id}: ${ap.title} [${ap.severity}]\nEntry: ${ap.entryPoint}\nMechanism: ${ap.mechanism.join("; ")}\nImpact: ${ap.impact}`,
    )
    .join("\n\n") || "(no attack paths found)";
}

// ---------------------------------------------------------------------------
// Recall Computation
// ---------------------------------------------------------------------------

async function computeRecall(
  items: MatchItem[],
  outputSection: string,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<{ recall: number; matched: string[]; missed: string[] }> {
  if (items.length === 0) return { recall: 1, matched: [], missed: [] };

  const results = await classifyMatches(items, outputSection, model, authConfig);

  const matched: string[] = [];
  const missed: string[] = [];
  for (const item of items) {
    const r = results.get(item.id);
    if (r?.matched) {
      matched.push(item.id);
    } else {
      missed.push(item.id);
    }
  }

  return {
    recall: matched.length / items.length,
    matched,
    missed,
  };
}

// ---------------------------------------------------------------------------
// Main Validator
// ---------------------------------------------------------------------------

export async function validateDiscovery(
  parsed: ParsedThreatModel,
  gt: CanonicalGroundTruth,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<DiscoveryScore> {
  // Feature recall
  const featureItems: MatchItem[] = gt.features.map((f) => ({
    id: f.id,
    description: `${f.name}: ${f.description}`,
  }));
  const featureResult = await computeRecall(
    featureItems,
    extractFeaturesSection(parsed),
    model,
    authConfig,
  );

  // Security control recall
  const controlItems: MatchItem[] = gt.securityControls.map((sc) => ({
    id: sc.id,
    description: `${sc.name} (${sc.type ?? "control"}): ${sc.description}`,
  }));
  const controlResult = await computeRecall(
    controlItems,
    extractControlsSection(parsed),
    model,
    authConfig,
  );

  // Trust boundary recall
  const boundaryItems: MatchItem[] = gt.trustBoundaries.map((tb, i) => ({
    id: tb.id ?? `tb-${i + 1}`,
    description: `${tb.name}: ${tb.description}`,
  }));
  const boundaryResult = await computeRecall(
    boundaryItems,
    extractBoundariesSection(parsed),
    model,
    authConfig,
  );

  // Component recall
  const componentSection = parsed.components
    .map((c) => `${c.id} ${c.name}: ${c.type} (${c.technology})`)
    .join("\n");
  // For components we just check if there are reasonable matches — skip LLM for now
  const componentRecall =
    parsed.components.length > 0 ? Math.min(parsed.components.length / 3, 1) : 0;

  // VULNERABILITY RECALL — the most important metric
  const vulnItems: MatchItem[] = gt.plantedVulnerabilities
    .filter((v) => v.expectedInAttackPaths !== false)
    .map((v) => ({
      id: v.id,
      description: `${v.name} (${v.severity}): ${v.description}. Entry via: ${v.files.map((f) => f.path).join(", ")}`,
    }));
  const vulnResult = await computeRecall(
    vulnItems,
    extractAttackPathsSection(parsed),
    model,
    authConfig,
  );

  // FALSE POSITIVE RATE
  let falsePositiveRate = 0;
  if (gt.falsePositiveTraps.length > 0 && parsed.attackPaths.length > 0) {
    const fpItems: MatchItem[] = gt.falsePositiveTraps.map((fp) => ({
      id: fp.id,
      description: `False alarm on ${fp.file}: ${fp.name}. ${fp.shouldNotFlagAs ?? fp.pattern ?? ""}`,
    }));
    const fpResult = await classifyMatches(
      fpItems,
      extractAttackPathsSection(parsed),
      model,
      authConfig,
    );
    const fpCount = [...fpResult.values()].filter((r) => r.matched).length;
    falsePositiveRate = fpCount / gt.falsePositiveTraps.length;
  }

  // Adversarial resistance (TM-APP-010) — uses specialized classifier
  let adversarialResistance: number | undefined;
  if (gt.adversarialInjections && gt.adversarialInjections.length > 0) {
    const advItems: MatchItem[] = gt.adversarialInjections.map((a) => ({
      id: a.id,
      description: `FALSE CLAIM planted in codebase: "${a.claim}". Reality: ${a.reality}`,
    }));
    const advResults = await classifyAdversarial(
      advItems,
      parsed.raw.slice(0, 20000),
      model,
      authConfig,
    );
    // matched = model was fooled (parroted as fact). Higher resistance = better.
    const parroted = [...advResults.values()].filter((r) => r.matched).length;
    adversarialResistance =
      1 - parroted / gt.adversarialInjections.length;
  }

  // Base discovery score
  let score =
    featureResult.recall * 0.15 +
    controlResult.recall * 0.15 +
    boundaryResult.recall * 0.10 +
    componentRecall * 0.05 +
    vulnResult.recall * 0.40 +
    (1 - falsePositiveRate) * 0.15;

  // Apply adversarial penalty if applicable (parroting false claims tanks the score)
  if (adversarialResistance !== undefined) {
    const advPenalty = (1 - adversarialResistance) * 0.10;
    score = Math.max(0, score - advPenalty);
  }

  return {
    score,
    featureRecall: featureResult.recall,
    controlRecall: controlResult.recall,
    boundaryRecall: boundaryResult.recall,
    componentRecall,
    vulnerabilityRecall: vulnResult.recall,
    falsePositiveRate,
    missedVulnerabilities: vulnResult.missed,
    adversarialResistance,
  };
}
