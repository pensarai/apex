/**
 * Threat Model Benchmark — Structural Validator
 *
 * 12 automated checks on the parsed markdown output.
 * No LLM calls — fully deterministic.
 */

import type {
  ParsedThreatModel,
  CanonicalGroundTruth,
  StructuralScore,
} from "../types";

const REQUIRED_SECTIONS = [
  "application context",
  "deployment model",
  "system components",
  "trust boundaries",
  "data flow",
  "security control",
  "attack path",
  "summary",
];

function normalize(s: string): string {
  return s.toLowerCase().replace(/[\s_-]+/g, " ");
}

// ---------------------------------------------------------------------------
// Individual Checks
// ---------------------------------------------------------------------------

/** S-01: All 8 required sections present */
function checkSectionsPresent(parsed: ParsedThreatModel): number {
  let found = 0;
  for (const required of REQUIRED_SECTIONS) {
    if (
      parsed.sectionsFound.some((s) => normalize(s).includes(required))
    ) {
      found++;
    }
  }
  return found / REQUIRED_SECTIONS.length;
}

/** S-02: Metadata fields match ground truth expected identity */
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

/** S-03: Component IDs sequential (comp-1, comp-2, ...) */
function checkComponentIds(parsed: ParsedThreatModel): number {
  if (parsed.components.length === 0) return 0;
  const ids = parsed.components
    .map((c) => {
      const m = c.id.match(/comp-?(\d+)/i);
      return m ? parseInt(m[1], 10) : -1;
    })
    .filter((n) => n > 0)
    .sort((a, b) => a - b);
  if (ids.length === 0) return 0;
  // Check sequential from 1
  for (let i = 0; i < ids.length; i++) {
    if (ids[i] !== i + 1) return 0;
  }
  return 1;
}

/** S-04: Data flow from/to reference valid component IDs */
function checkDataFlowRefs(parsed: ParsedThreatModel): number {
  if (parsed.dataFlows.length === 0) return parsed.components.length > 0 ? 0 : 1;
  const compNames = new Set(
    parsed.components.map((c) => normalize(c.name)),
  );
  const compIds = new Set(
    parsed.components.map((c) => normalize(c.id)),
  );
  const validSet = new Set([...compNames, ...compIds]);

  let valid = 0;
  let total = 0;
  for (const df of parsed.dataFlows) {
    if (df.from) {
      total++;
      if (validSet.has(normalize(df.from))) valid++;
    }
    if (df.to) {
      total++;
      if (validSet.has(normalize(df.to))) valid++;
    }
  }
  return total > 0 ? valid / total : 1;
}

/** S-05: Attack path IDs sequential */
function checkAttackPathIds(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const ids = parsed.attackPaths
    .map((ap) => {
      const m = ap.id.match(/AP-?(\d+)/i);
      return m ? parseInt(m[1], 10) : -1;
    })
    .filter((n) => n > 0)
    .sort((a, b) => a - b);
  if (ids.length === 0) return 0;
  for (let i = 0; i < ids.length; i++) {
    if (ids[i] !== i + 1) return 0;
  }
  return 1;
}

/** S-06: Each AP has all required subsections */
function checkAttackPathSubsections(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const keys: (keyof typeof parsed.attackPaths[0]["subsectionsPresent"])[] = [
    "mechanism",
    "impact",
    "preconditions",
    "existingControls",
    "controlGaps",
    "pentestGuidance",
  ];
  let total = 0;
  let present = 0;
  for (const ap of parsed.attackPaths) {
    for (const key of keys) {
      total++;
      if (ap.subsectionsPresent[key]) present++;
    }
  }
  return total > 0 ? present / total : 0;
}

/** S-07: SC-IDs referenced in at least one AP's existing controls */
function checkScReferences(parsed: ParsedThreatModel): number {
  if (parsed.securityControls.length === 0) return 0;
  const allControlText = parsed.attackPaths
    .flatMap((ap) => ap.existingControls)
    .join(" ");

  let referenced = 0;
  for (const sc of parsed.securityControls) {
    if (allControlText.includes(sc.id)) referenced++;
  }
  return referenced / parsed.securityControls.length;
}

/** S-08: Summary table counts match actual body */
function checkSummaryCounts(parsed: ParsedThreatModel): number {
  let checks = 0;
  let correct = 0;

  if (parsed.summary.components !== undefined) {
    checks++;
    if (parsed.summary.components === parsed.components.length) correct++;
  }
  if (parsed.summary.dataFlows !== undefined) {
    checks++;
    if (parsed.summary.dataFlows === parsed.dataFlows.length) correct++;
  }
  if (parsed.summary.attackPaths !== undefined) {
    checks++;
    if (parsed.summary.attackPaths === parsed.attackPaths.length) correct++;
  }

  return checks > 0 ? correct / checks : 0;
}

/** S-09: Attack path count in [8, 15] */
function checkAttackPathCount(parsed: ParsedThreatModel): number {
  const count = parsed.attackPaths.length;
  return count >= 8 && count <= 15 ? 1 : 0;
}

/** S-10: Mechanism step count >= 8 per path */
function checkMechanismSteps(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  let total = 0;
  for (const ap of parsed.attackPaths) {
    // 8+ steps = 1.0, scale down linearly below 8
    total += Math.min(ap.mechanism.length / 8, 1);
  }
  return total / parsed.attackPaths.length;
}

/** S-11: Severity distribution has >= 2 distinct levels */
function checkSeverityDistribution(parsed: ParsedThreatModel): number {
  const severities = new Set(
    parsed.attackPaths.map((ap) => ap.severity.toLowerCase()),
  );
  return severities.size >= 2 ? 1 : 0;
}

/** S-12: Attacker profile count in [3, 5] */
function checkAttackerProfileCount(parsed: ParsedThreatModel): number {
  const count = parsed.attackerProfiles.length;
  return count >= 3 && count <= 5 ? 1 : 0;
}

/** S-13: Mechanism steps have substantive content (30+ chars each) */
function checkMechanismStepDepth(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const MIN_STEP_LENGTH = 30;
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

/** S-14: Security controls have non-empty gap analysis */
function checkControlGapsPresent(parsed: ParsedThreatModel): number {
  if (parsed.securityControls.length === 0) return 0;
  let withGaps = 0;
  for (const sc of parsed.securityControls) {
    if (sc.gaps && sc.gaps.trim().length > 10) withGaps++;
  }
  return withGaps / parsed.securityControls.length;
}

// ---------------------------------------------------------------------------
// Main Validator
// ---------------------------------------------------------------------------

export function validateStructural(
  parsed: ParsedThreatModel,
  gt: CanonicalGroundTruth,
): StructuralScore {
  const checks: Record<string, number> = {
    sections_present: checkSectionsPresent(parsed),
    metadata_correct: checkMetadataCorrect(parsed, gt),
    component_ids_sequential: checkComponentIds(parsed),
    dataflow_refs_valid: checkDataFlowRefs(parsed),
    attack_path_ids_sequential: checkAttackPathIds(parsed),
    attack_path_subsections: checkAttackPathSubsections(parsed),
    sc_ids_referenced: checkScReferences(parsed),
    summary_counts_match: checkSummaryCounts(parsed),
    attack_path_count: checkAttackPathCount(parsed),
    mechanism_steps: checkMechanismSteps(parsed),
    severity_distribution: checkSeverityDistribution(parsed),
    attacker_profile_count: checkAttackerProfileCount(parsed),
    mechanism_step_depth: checkMechanismStepDepth(parsed),
    control_gaps_present: checkControlGapsPresent(parsed),
  };

  const values = Object.values(checks);
  const score = values.reduce((a, b) => a + b, 0) / values.length;

  return { score, checks };
}
