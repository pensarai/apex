/**
 * CVSS 4.0 Score Calculator
 *
 * Implements the MacroVector-based scoring algorithm from the FIRST specification.
 * The spec leaves the interpolation constants to the reference implementation, so
 * this tracks RedHatProductSecurity/cvss-v4-calculator `cvss40.js` - the calculator
 * FIRST hosts - which `calculator.test.ts` pins it to.
 *
 * Reference: https://www.first.org/cvss/v4-0/specification-document
 */

import {
  EPSILON,
  MACROVECTOR_LOOKUP,
  MAX_COMPOSED,
  MAX_SEVERITY,
  METRIC_LEVELS,
  NO_IMPACT_METRICS,
  STEP,
} from "./macrovector-scores";
import type { CVSS4Metrics, CVSS4Score, CVSS4ScoreType } from "./types";
import { getSeverityFromScore } from "./types";

// =============================================================================
// Metric Ordering (required order for vector string)
// =============================================================================

const BASE_METRICS = [
  "AV",
  "AC",
  "AT",
  "PR",
  "UI",
  "VC",
  "VI",
  "VA",
  "SC",
  "SI",
  "SA",
] as const;
const THREAT_METRICS = ["E"] as const;
const ENVIRONMENTAL_METRICS = [
  "CR",
  "IR",
  "AR",
  "MAV",
  "MAC",
  "MAT",
  "MPR",
  "MUI",
  "MVC",
  "MVI",
  "MVA",
  "MSC",
  "MSI",
  "MSA",
] as const;
const SUPPLEMENTAL_METRICS = ["S", "AU", "R", "V", "RE", "U"] as const;

const KNOWN_METRICS: ReadonlySet<string> = new Set([
  ...BASE_METRICS,
  ...THREAT_METRICS,
  ...ENVIRONMENTAL_METRICS,
  ...SUPPLEMENTAL_METRICS,
]);

// =============================================================================
// Vector String Functions
// =============================================================================

/**
 * Build CVSS 4.0 vector string from metrics
 */
export function buildVectorString(metrics: CVSS4Metrics): string {
  const parts: string[] = ["CVSS:4.0"];

  // Add base metrics (required)
  for (const metric of BASE_METRICS) {
    const value = metrics[metric as keyof CVSS4Metrics];
    if (value !== undefined) {
      parts.push(`${metric}:${value}`);
    }
  }

  // Add threat metrics (optional)
  for (const metric of THREAT_METRICS) {
    const value = metrics[metric as keyof CVSS4Metrics];
    if (value !== undefined && value !== "X") {
      parts.push(`${metric}:${value}`);
    }
  }

  // Add environmental metrics (optional)
  for (const metric of ENVIRONMENTAL_METRICS) {
    const value = metrics[metric as keyof CVSS4Metrics];
    if (value !== undefined && value !== "X") {
      parts.push(`${metric}:${value}`);
    }
  }

  // Add supplemental metrics (optional)
  for (const metric of SUPPLEMENTAL_METRICS) {
    const value = metrics[metric as keyof CVSS4Metrics];
    if (value !== undefined && value !== "X") {
      parts.push(`${metric}:${value}`);
    }
  }

  return parts.join("/");
}

/**
 * Parse CVSS 4.0 vector string into metrics
 */
export function parseVectorString(vectorString: string): CVSS4Metrics {
  if (!vectorString.startsWith("CVSS:4.0/")) {
    throw new Error(
      "Invalid CVSS 4.0 vector string: must start with CVSS:4.0/",
    );
  }

  const metricsString = vectorString.substring("CVSS:4.0/".length);
  const pairs = metricsString.split("/");

  const metrics: Partial<CVSS4Metrics> = {};
  const seen = new Set<string>();

  for (const pair of pairs) {
    const [key, value] = pair.split(":");
    if (!key || !value) {
      throw new Error(`Malformed metric in CVSS vector: "${pair}"`);
    }
    if (!KNOWN_METRICS.has(key)) {
      throw new Error(`Unknown metric in CVSS vector: ${key}`);
    }
    // A repeated metric would otherwise last-write-win and yield a plausible
    // wrong score instead of an error.
    if (seen.has(key)) {
      throw new Error(`Duplicate metric in CVSS vector: ${key}`);
    }
    seen.add(key);
    (metrics as Record<string, string | undefined>)[key] = value;
  }

  // Validate required base metrics
  for (const metric of BASE_METRICS) {
    if (!(metric in metrics)) {
      throw new Error(`Missing required base metric: ${metric}`);
    }
  }

  return metrics as CVSS4Metrics;
}

// =============================================================================
// Equivalence Class Computation
// =============================================================================

/** Metrics whose Not Defined value resolves to a worst-case assumption */
const WORST_CASE_DEFAULTS: Record<string, string> = {
  E: "A",
  CR: "H",
  IR: "H",
  AR: "H",
};

/**
 * Get effective metric value: the modified metric when set, otherwise the base
 * metric, with `X` resolved to its worst-case default where one is defined.
 */
function getEffectiveValue(metrics: CVSS4Metrics, metric: string): string {
  const record = metrics as unknown as Record<string, string | undefined>;
  const selected = record[metric] ?? "X";

  const worstCase = WORST_CASE_DEFAULTS[metric];
  if (worstCase !== undefined && selected === "X") {
    return worstCase;
  }

  const modified = record[`M${metric}`];
  if (modified !== undefined && modified !== "X") {
    return modified;
  }

  return selected;
}

/**
 * Compute equivalence class 1 (Exploitability)
 * Based on AV, PR, UI
 */
function computeEQ1(metrics: CVSS4Metrics): number {
  const av = getEffectiveValue(metrics, "AV");
  const pr = getEffectiveValue(metrics, "PR");
  const ui = getEffectiveValue(metrics, "UI");

  // EQ1 = 0: AV:N AND PR:N AND UI:N
  if (av === "N" && pr === "N" && ui === "N") {
    return 0;
  }

  // EQ1 = 1: (AV:N OR PR:N OR UI:N) AND NOT (AV:N AND PR:N AND UI:N) AND AV != P
  if ((av === "N" || pr === "N" || ui === "N") && av !== "P") {
    return 1;
  }

  // EQ1 = 2: AV:P OR NOT (AV:N OR PR:N OR UI:N)
  return 2;
}

/**
 * Compute equivalence class 2 (Complexity)
 * Based on AC, AT
 */
function computeEQ2(metrics: CVSS4Metrics): number {
  const ac = getEffectiveValue(metrics, "AC");
  const at = getEffectiveValue(metrics, "AT");

  // EQ2 = 0: AC:L AND AT:N
  if (ac === "L" && at === "N") {
    return 0;
  }

  // EQ2 = 1: NOT (AC:L AND AT:N)
  return 1;
}

/**
 * Compute equivalence class 3 (Vulnerable System Impact)
 * Based on VC, VI, VA
 */
function computeEQ3(metrics: CVSS4Metrics): number {
  const vc = getEffectiveValue(metrics, "VC");
  const vi = getEffectiveValue(metrics, "VI");
  const va = getEffectiveValue(metrics, "VA");

  // EQ3 = 0: VC:H AND VI:H
  if (vc === "H" && vi === "H") {
    return 0;
  }

  // EQ3 = 1: NOT (VC:H AND VI:H) AND (VC:H OR VI:H OR VA:H)
  if (vc === "H" || vi === "H" || va === "H") {
    return 1;
  }

  // EQ3 = 2: NOT (VC:H OR VI:H OR VA:H)
  return 2;
}

/**
 * Compute equivalence class 4 (Subsequent System Impact)
 * Based on SC, SI, SA (using modified values if set)
 */
function computeEQ4(metrics: CVSS4Metrics): number {
  const msi = getEffectiveValue(metrics, "MSI");
  const msa = getEffectiveValue(metrics, "MSA");
  const sc = getEffectiveValue(metrics, "SC");
  const si = getEffectiveValue(metrics, "SI");
  const sa = getEffectiveValue(metrics, "SA");

  // EQ4 = 0: MSI:S OR MSA:S
  if (msi === "S" || msa === "S") {
    return 0;
  }

  // EQ4 = 1: NOT (MSI:S OR MSA:S) AND (SC:H OR SI:H OR SA:H)
  if (sc === "H" || si === "H" || sa === "H") {
    return 1;
  }

  // EQ4 = 2: NOT (SC:H OR SI:H OR SA:H)
  return 2;
}

/**
 * Compute equivalence class 5 (Exploitation Maturity)
 * Based on E
 */
function computeEQ5(metrics: CVSS4Metrics): number {
  const e = getEffectiveValue(metrics, "E");

  if (e === "A") {
    return 0;
  }
  if (e === "P") {
    return 1;
  }
  // E:U
  return 2;
}

/**
 * Compute equivalence class 6 (Security Requirements combined with Impact)
 * Based on CR, IR, AR and VC, VI, VA
 */
function computeEQ6(metrics: CVSS4Metrics): number {
  const cr = getEffectiveValue(metrics, "CR");
  const ir = getEffectiveValue(metrics, "IR");
  const ar = getEffectiveValue(metrics, "AR");

  const vc = getEffectiveValue(metrics, "VC");
  const vi = getEffectiveValue(metrics, "VI");
  const va = getEffectiveValue(metrics, "VA");

  // EQ6 = 0: (CR:H AND VC:H) OR (IR:H AND VI:H) OR (AR:H AND VA:H)
  if (
    (cr === "H" && vc === "H") ||
    (ir === "H" && vi === "H") ||
    (ar === "H" && va === "H")
  ) {
    return 0;
  }

  // EQ6 = 1: NOT above condition
  return 1;
}

/**
 * Compute the 6-digit MacroVector from metrics
 */
export function computeMacroVector(metrics: CVSS4Metrics): string {
  const eq1 = computeEQ1(metrics);
  const eq2 = computeEQ2(metrics);
  const eq3 = computeEQ3(metrics);
  const eq4 = computeEQ4(metrics);
  const eq5 = computeEQ5(metrics);
  const eq6 = computeEQ6(metrics);

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
}

// =============================================================================
// Score Interpolation
// =============================================================================

/**
 * Check if all impact metrics are None (score should be 0)
 */
function hasNoImpact(metrics: CVSS4Metrics): boolean {
  return NO_IMPACT_METRICS.every(
    (metric) => getEffectiveValue(metrics, metric) === "N",
  );
}

interface MacroVectorParts {
  eq1: number;
  eq2: number;
  eq3: number;
  eq4: number;
  eq5: number;
  eq6: number;
}

function parseMacroVector(macroVector: string): MacroVectorParts {
  return {
    eq1: Number(macroVector[0]),
    eq2: Number(macroVector[1]),
    eq3: Number(macroVector[2]),
    eq4: Number(macroVector[3]),
    eq5: Number(macroVector[4]),
    eq6: Number(macroVector[5]),
  };
}

/**
 * Score of the MacroVector one step below on the given equivalence classes,
 * or undefined when no such MacroVector exists.
 */
function lowerMacroVectorScore(
  eq: MacroVectorParts,
  step: Partial<MacroVectorParts>,
): number | undefined {
  const stepped = { ...eq, ...step };
  return MACROVECTOR_LOOKUP[
    `${stepped.eq1}${stepped.eq2}${stepped.eq3}${stepped.eq4}${stepped.eq5}${stepped.eq6}`
  ];
}

/**
 * EQ3 and EQ6 are not independent, so stepping down means stepping EQ3, EQ6,
 * or - when both are 0 - whichever of the two single steps scores higher.
 */
function lowerEq3Eq6Score(eq: MacroVectorParts): number | undefined {
  if (eq.eq3 === 0 && eq.eq6 === 0) {
    const viaEq6 = lowerMacroVectorScore(eq, { eq6: eq.eq6 + 1 });
    const viaEq3 = lowerMacroVectorScore(eq, { eq3: eq.eq3 + 1 });
    if (viaEq6 === undefined || viaEq3 === undefined) {
      return undefined;
    }
    return Math.max(viaEq6, viaEq3);
  }
  if (eq.eq3 === 1 && eq.eq6 === 0) {
    return lowerMacroVectorScore(eq, { eq6: eq.eq6 + 1 });
  }
  if (eq.eq3 < 2) {
    return lowerMacroVectorScore(eq, { eq3: eq.eq3 + 1 });
  }
  return lowerMacroVectorScore(eq, { eq3: eq.eq3 + 1, eq6: eq.eq6 + 1 });
}

/**
 * Every highest-severity vector of this MacroVector, as the cross product of
 * the per-equivalence-class maxima. EQ3's set is also indexed by EQ6.
 */
function composeMaxVectors(eq: MacroVectorParts): string[] {
  const eq3Maxima = MAX_COMPOSED.eq3[eq.eq3]?.[eq.eq6];
  if (eq3Maxima === undefined) {
    throw new Error(`No max severity vector for eq3=${eq.eq3}, eq6=${eq.eq6}`);
  }

  const vectors: string[] = [];
  for (const eq1Max of MAX_COMPOSED.eq1[eq.eq1]) {
    for (const eq2Max of MAX_COMPOSED.eq2[eq.eq2]) {
      for (const eq3Max of eq3Maxima) {
        for (const eq4Max of MAX_COMPOSED.eq4[eq.eq4]) {
          for (const eq5Max of MAX_COMPOSED.eq5[eq.eq5]) {
            vectors.push(eq1Max + eq2Max + eq3Max + eq4Max + eq5Max);
          }
        }
      }
    }
  }
  return vectors;
}

/**
 * Read a metric's value out of a composed max-severity vector
 */
function extractMaxVectorValue(metric: string, maxVector: string): string {
  const start = maxVector.indexOf(`${metric}:`);
  if (start < 0) {
    throw new Error(`Metric ${metric} missing from max vector ${maxVector}`);
  }
  const rest = maxVector.slice(start + metric.length + 1);
  const end = rest.indexOf("/");
  return end > 0 ? rest.slice(0, end) : rest;
}

/**
 * Per-metric severity distance between the scored vector and a max vector
 */
function severityDistances(
  metrics: CVSS4Metrics,
  maxVector: string,
): Record<string, number> {
  const distances: Record<string, number> = {};

  for (const [metric, levels] of Object.entries(METRIC_LEVELS)) {
    const value = getEffectiveValue(metrics, metric);
    const maxValue = extractMaxVectorValue(metric, maxVector);
    const level = levels[value];
    const maxLevel = levels[maxValue];
    if (level === undefined) {
      throw new Error(`Unknown value ${metric}:${value}`);
    }
    if (maxLevel === undefined) {
      throw new Error(`Unknown value ${metric}:${maxValue} in ${maxVector}`);
    }
    distances[metric] = level - maxLevel;
  }

  return distances;
}

/**
 * Calculate the interpolated CVSS score
 */
function interpolateScore(
  metrics: CVSS4Metrics,
  macroVector: string,
  macroScore: number,
): number {
  const eq = parseMacroVector(macroVector);

  // The max vector is the first highest-severity vector of this MacroVector
  // that the scored vector does not exceed on any metric.
  let distances: Record<string, number> | undefined;
  for (const maxVector of composeMaxVectors(eq)) {
    distances = severityDistances(metrics, maxVector);
    if (Object.values(distances).every((distance) => distance >= 0)) {
      break;
    }
  }
  if (distances === undefined) {
    throw new Error(`No max vectors composed for MacroVector ${macroVector}`);
  }

  const severityDistance = {
    eq1: distances.AV + distances.PR + distances.UI,
    eq2: distances.AC + distances.AT,
    eq3eq6:
      distances.VC +
      distances.VI +
      distances.VA +
      distances.CR +
      distances.IR +
      distances.AR,
    eq4: distances.SC + distances.SI + distances.SA,
  };

  const lowerScore = {
    eq1: lowerMacroVectorScore(eq, { eq1: eq.eq1 + 1 }),
    eq2: lowerMacroVectorScore(eq, { eq2: eq.eq2 + 1 }),
    eq3eq6: lowerEq3Eq6Score(eq),
    eq4: lowerMacroVectorScore(eq, { eq4: eq.eq4 + 1 }),
  };

  const macroVectorDepth = {
    eq1: MAX_SEVERITY.eq1[eq.eq1] * STEP,
    eq2: MAX_SEVERITY.eq2[eq.eq2] * STEP,
    eq3eq6: MAX_SEVERITY.eq3eq6[eq.eq3][eq.eq6] * STEP,
    eq4: MAX_SEVERITY.eq4[eq.eq4] * STEP,
  };

  let existingLowerCount = 0;
  let proportionalDistance = 0;

  for (const key of ["eq1", "eq2", "eq3eq6", "eq4"] as const) {
    const lower = lowerScore[key];
    if (lower === undefined) {
      continue;
    }
    existingLowerCount++;
    proportionalDistance +=
      (macroScore - lower) * (severityDistance[key] / macroVectorDepth[key]);
  }

  // EQ5's proportion is always 0, so it only widens the mean.
  if (lowerMacroVectorScore(eq, { eq5: eq.eq5 + 1 }) !== undefined) {
    existingLowerCount++;
  }

  const meanDistance =
    existingLowerCount === 0 ? 0 : proportionalDistance / existingLowerCount;

  const score = Math.max(0, Math.min(10, macroScore - meanDistance));
  return Math.round((score + EPSILON) * 10) / 10;
}

// =============================================================================
// Main Calculator Function
// =============================================================================

/**
 * Calculate CVSS 4.0 score from metrics
 */
export function calculateCVSS4Score(metrics: CVSS4Metrics): CVSS4Score {
  // Check for zero score (no impact)
  if (hasNoImpact(metrics)) {
    return {
      score: 0,
      severity: "NONE",
      vectorString: buildVectorString(metrics),
      metrics,
      scoreType: getScoreType(metrics),
    };
  }

  // Compute MacroVector
  const macroVector = computeMacroVector(metrics);

  // Look up base score
  const baseScore = MACROVECTOR_LOOKUP[macroVector];
  if (baseScore === undefined) {
    throw new Error(`Invalid MacroVector: ${macroVector}`);
  }

  // Interpolate final score
  const score = interpolateScore(metrics, macroVector, baseScore);
  const severity = getSeverityFromScore(score);
  const scoreType = getScoreType(metrics);

  return {
    score,
    severity,
    vectorString: buildVectorString(metrics),
    metrics,
    scoreType,
  };
}

/**
 * Determine score type based on which metrics are provided
 */
function getScoreType(metrics: CVSS4Metrics): CVSS4ScoreType {
  const hasThreat = metrics.E !== undefined && metrics.E !== "X";
  const hasEnvironmental =
    (metrics.CR !== undefined && metrics.CR !== "X") ||
    (metrics.IR !== undefined && metrics.IR !== "X") ||
    (metrics.AR !== undefined && metrics.AR !== "X") ||
    (metrics.MAV !== undefined && metrics.MAV !== "X") ||
    (metrics.MAC !== undefined && metrics.MAC !== "X") ||
    (metrics.MAT !== undefined && metrics.MAT !== "X") ||
    (metrics.MPR !== undefined && metrics.MPR !== "X") ||
    (metrics.MUI !== undefined && metrics.MUI !== "X") ||
    (metrics.MVC !== undefined && metrics.MVC !== "X") ||
    (metrics.MVI !== undefined && metrics.MVI !== "X") ||
    (metrics.MVA !== undefined && metrics.MVA !== "X") ||
    (metrics.MSC !== undefined && metrics.MSC !== "X") ||
    (metrics.MSI !== undefined && metrics.MSI !== "X") ||
    (metrics.MSA !== undefined && metrics.MSA !== "X");

  if (hasThreat && hasEnvironmental) return "CVSS-BTE";
  if (hasEnvironmental) return "CVSS-BE";
  if (hasThreat) return "CVSS-BT";
  return "CVSS-B";
}

// =============================================================================
// Validation
// =============================================================================

/**
 * Validate that all required base metrics are present
 */
export function validateMetrics(
  metrics: Partial<CVSS4Metrics>,
): metrics is CVSS4Metrics {
  const requiredMetrics = [
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
  ];
  for (const metric of requiredMetrics) {
    if (
      !(metric in metrics) ||
      (metrics as unknown as Record<string, string | undefined>)[metric] ===
        undefined
    ) {
      return false;
    }
  }
  return true;
}
