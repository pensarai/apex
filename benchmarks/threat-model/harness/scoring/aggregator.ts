/**
 * Threat Model Benchmark — Score Aggregator
 *
 * Combines dimension scores into category and overall scores.
 * Supports app-specific weight overrides from ground truth.
 */

import type {
  AppScorecard,
  CanonicalGroundTruth,
  StructuralScore,
  GroundingScore,
  AntiPatternScore,
  DiscoveryScore,
  AttackPathJudgeScore,
  EffectivenessScore,
  BehavioralMetrics,
  HeadlineMetrics,
} from "../types";

// ---------------------------------------------------------------------------
// Default Weights
// ---------------------------------------------------------------------------

const DEFAULT_WEIGHTS = {
  structural: 0.10,
  grounding: 0.30,
  antipattern: 0.05,
  discovery: 0.25,
  attackPathDepth: 0.25,
  effectiveness: 0.05,
};

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/** Normalize LLM judge scores (1-5) to 0-1 */
function normJudge(score: number): number {
  return Math.max(0, Math.min(1, (score - 1) / 4));
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

export function aggregateAppScores(opts: {
  appId: string;
  gt: CanonicalGroundTruth;
  structural: StructuralScore | null;
  grounding: GroundingScore | null;
  antipattern: AntiPatternScore | null;
  discovery: DiscoveryScore | null;
  attackPathDepth: AttackPathJudgeScore | null;
  effectiveness: EffectivenessScore | null;
  behavioral: BehavioralMetrics;
}): AppScorecard {
  const {
    appId,
    gt,
    structural,
    grounding,
    antipattern,
    discovery,
    attackPathDepth,
    effectiveness,
    behavioral,
  } = opts;

  // Build dimension scores map (0-1 normalized)
  const dimensions: Record<string, number | null> = {
    structural: structural?.score ?? null,
    grounding: grounding?.score ?? null,
    antipattern: antipattern?.score ?? null,
    discovery: discovery?.score ?? null,
    attackPathDepth: attackPathDepth
      ? normJudge(attackPathDepth.score)
      : null,
    effectiveness: effectiveness ? normJudge(effectiveness.score) : null,
  };

  // Use app-specific weights if available, otherwise defaults
  const weights = { ...DEFAULT_WEIGHTS };
  if (gt.scoringOverrides?.weights) {
    const overrides = gt.scoringOverrides.weights;
    // Map app-specific weight keys to standard dimension names
    if (overrides.vulnerability_recall !== undefined)
      weights.discovery = overrides.vulnerability_recall;
    if (overrides.adversarial_resistance !== undefined)
      weights.antipattern = overrides.adversarial_resistance;
    if (overrides.control_recognition !== undefined)
      weights.grounding =
        (overrides.control_recognition ?? 0) +
        (overrides.boundary_identification ?? 0);
    if (overrides.attacker_profiling !== undefined)
      weights.effectiveness = overrides.attacker_profiling;
    if (overrides.attack_path_quality !== undefined)
      weights.attackPathDepth = overrides.attack_path_quality;

    // Renormalize weights to sum to 1
    const sum = Object.values(weights).reduce((a, b) => a + b, 0);
    if (sum > 0) {
      for (const key of Object.keys(weights) as (keyof typeof weights)[]) {
        weights[key] /= sum;
      }
    }
  }

  // Compute weighted overall — only include non-null dimensions
  let weightedSum = 0;
  let weightSum = 0;
  for (const [key, weight] of Object.entries(weights)) {
    const dimScore = dimensions[key];
    if (dimScore !== null) {
      weightedSum += dimScore * weight;
      weightSum += weight;
    }
  }

  const overall = weightSum > 0 ? (weightedSum / weightSum) * 100 : 0;

  return {
    appId,
    status: "completed",
    overall,
    structural,
    grounding,
    antipattern,
    discovery,
    attackPathDepth,
    effectiveness,
    behavioral,
  };
}

export function aggregateHeadlineMetrics(
  scorecards: AppScorecard[],
): HeadlineMetrics {
  const completed = scorecards.filter((s) => s.status === "completed");
  if (completed.length === 0) {
    return {
      overallScore: 0,
      vulnerabilityRecall: 0,
      falsePositiveRate: 0,
      groundingScore: 0,
      totalCostUsd: 0,
    };
  }

  const avg = (arr: number[]) =>
    arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;

  return {
    overallScore: avg(completed.map((s) => s.overall)),
    vulnerabilityRecall: avg(
      completed
        .map((s) => s.discovery?.vulnerabilityRecall)
        .filter((v): v is number => v !== undefined),
    ),
    falsePositiveRate: avg(
      completed
        .map((s) => s.discovery?.falsePositiveRate)
        .filter((v): v is number => v !== undefined),
    ),
    groundingScore: avg(
      completed
        .map((s) => s.grounding?.score)
        .filter((v): v is number => v !== undefined),
    ),
    totalCostUsd: completed.reduce(
      (sum, s) => sum + (s.behavioral.tokens?.estimatedCostUsd ?? 0),
      0,
    ),
  };
}
