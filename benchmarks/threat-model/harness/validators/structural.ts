/**
 * Threat Model Benchmark — Structural Validator (v3)
 *
 * 8 checks that actually discriminate quality.
 * Removed 8 always-passing or parser-broken checks from v2.
 * No LLM calls — fully deterministic.
 */

import type {
  ParsedThreatModel,
  CanonicalGroundTruth,
  StructuralScore,
} from "../types";

function normalize(s: string): string {
  return s.toLowerCase().replace(/[\s_-]+/g, " ");
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/** Metadata fields match ground truth expected identity */
function checkMetadataCorrect(
  parsed: ParsedThreatModel,
  gt: CanonicalGroundTruth,
): number {
  const ei = gt.expectedIdentity;
  let total = 0;
  let correct = 0;

  if (ei.type) {
    total++;
    if (
      parsed.metadata.type &&
      normalize(parsed.metadata.type).includes(normalize(ei.type))
    )
      correct++;
  }

  if (ei.domain) {
    total++;
    if (
      parsed.metadata.domain &&
      normalize(parsed.metadata.domain).includes(normalize(ei.domain))
    )
      correct++;
  }

  if (ei.repoType) {
    total++;
    if (
      parsed.metadata.repoType &&
      normalize(parsed.metadata.repoType).includes(normalize(ei.repoType))
    )
      correct++;
  }

  if (ei.packageManagers.length > 0) {
    total++;
    if (
      parsed.metadata.packageManager &&
      ei.packageManagers.some((pm) =>
        normalize(parsed.metadata.packageManager!).includes(normalize(pm)),
      )
    )
      correct++;
  }

  return total > 0 ? correct / total : 1;
}

/** SC referenced in attack paths — fuzzy name matching (not just ID substring) */
function checkScReferences(parsed: ParsedThreatModel): number {
  if (parsed.securityControls.length === 0) return 0;
  const allControlText = parsed.attackPaths
    .flatMap((ap) => [...ap.existingControls, ap.pentestGuidance])
    .join(" ")
    .toLowerCase();

  let referenced = 0;
  for (const sc of parsed.securityControls) {
    // Match by ID or by control name (fuzzy)
    const idMatch = allControlText.includes(sc.id.toLowerCase());
    const nameMatch =
      sc.name.length > 4 &&
      allControlText.includes(sc.name.toLowerCase());
    if (idMatch || nameMatch) referenced++;
  }
  return referenced / parsed.securityControls.length;
}

/** Mechanism step count >= 8 per path (linear scale) */
function checkMechanismSteps(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  let total = 0;
  for (const ap of parsed.attackPaths) {
    total += Math.min(ap.mechanism.length / 8, 1);
  }
  return total / parsed.attackPaths.length;
}

/** Attacker profile count in [3, 6] */
function checkAttackerProfileCount(parsed: ParsedThreatModel): number {
  const count = parsed.attackerProfiles.length;
  return count >= 3 && count <= 6 ? 1 : 0;
}

/** Mechanism steps have substantive content (50+ chars each) */
function checkMechanismStepDepth(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const MIN_STEP_LENGTH = 50;
  let totalSteps = 0;
  let substantiveSteps = 0;
  for (const ap of parsed.attackPaths) {
    for (const step of ap.mechanism) {
      totalSteps++;
      if (step.length >= MIN_STEP_LENGTH) substantiveSteps++;
    }
  }
  return totalSteps > 0 ? substantiveSteps / totalSteps : 0;
}

/** Security controls have substantive gap analysis (50+ chars) */
function checkControlGapsPresent(parsed: ParsedThreatModel): number {
  if (parsed.securityControls.length === 0) return 0;
  let withGaps = 0;
  for (const sc of parsed.securityControls) {
    if (sc.gaps && sc.gaps.trim().length > 50) withGaps++;
  }
  return withGaps / parsed.securityControls.length;
}

/** Each AP has severity AND non-empty impact (severity without impact is meaningless) */
function checkSeverityJustified(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  let justified = 0;
  for (const ap of parsed.attackPaths) {
    if (ap.severity && ap.impact && ap.impact.length >= 30) justified++;
  }
  return justified / parsed.attackPaths.length;
}

/** Features table has >= 3 entries with non-empty security relevance */
function checkFeaturesPopulated(parsed: ParsedThreatModel): number {
  const substantive = parsed.features.filter(
    (f) => f.name.length > 0 && f.securityRelevance.length > 10,
  );
  if (substantive.length >= 5) return 1;
  if (substantive.length >= 3) return 0.6;
  if (substantive.length >= 1) return 0.3;
  return 0;
}

// ---------------------------------------------------------------------------
// Main Validator
// ---------------------------------------------------------------------------

export function validateStructural(
  parsed: ParsedThreatModel,
  gt: CanonicalGroundTruth,
): StructuralScore {
  const checks: Record<string, number> = {
    metadata_correct: checkMetadataCorrect(parsed, gt),
    sc_ids_referenced: checkScReferences(parsed),
    mechanism_steps: checkMechanismSteps(parsed),
    attacker_profile_count: checkAttackerProfileCount(parsed),
    mechanism_step_depth: checkMechanismStepDepth(parsed),
    control_gaps_present: checkControlGapsPresent(parsed),
    severity_justified: checkSeverityJustified(parsed),
    features_populated: checkFeaturesPopulated(parsed),
  };

  const values = Object.values(checks);
  const score = values.reduce((a, b) => a + b, 0) / values.length;

  return { score, checks };
}
