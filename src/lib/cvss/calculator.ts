/**
 * CVSS 4.0 Score Calculator
 *
 * Implements the MacroVector-based scoring algorithm from the FIRST specification.
 * Reference: https://www.first.org/cvss/v4-0/specification-document
 */

import type {
  CVSS4Metrics,
  CVSS4Score,
  CVSS4ScoreType,
  CVSS4Severity,
} from './types';
import { getSeverityFromScore } from './types';
import {
  MACROVECTOR_LOOKUP,
  METRIC_LEVELS,
  MAX_SEVERITY,
  MAX_COMPOSED,
  NO_IMPACT_METRICS,
  STEP,
  EPSILON,
} from './macrovector-scores';

// =============================================================================
// Metric Ordering (required order for vector string)
// =============================================================================

const BASE_METRICS = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as const;
const THREAT_METRICS = ['E'] as const;
const ENVIRONMENTAL_METRICS = [
  'CR',
  'IR',
  'AR',
  'MAV',
  'MAC',
  'MAT',
  'MPR',
  'MUI',
  'MVC',
  'MVI',
  'MVA',
  'MSC',
  'MSI',
  'MSA',
] as const;
const SUPPLEMENTAL_METRICS = ['S', 'AU', 'R', 'V', 'RE', 'U'] as const;

// =============================================================================
// Vector String Functions
// =============================================================================

/**
 * Build CVSS 4.0 vector string from metrics
 */
export function buildVectorString(metrics: CVSS4Metrics): string {
  const parts: string[] = ['CVSS:4.0'];

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
    if (value !== undefined && value !== 'X') {
      parts.push(`${metric}:${value}`);
    }
  }

  // Add environmental metrics (optional)
  for (const metric of ENVIRONMENTAL_METRICS) {
    const value = metrics[metric as keyof CVSS4Metrics];
    if (value !== undefined && value !== 'X') {
      parts.push(`${metric}:${value}`);
    }
  }

  // Add supplemental metrics (optional)
  for (const metric of SUPPLEMENTAL_METRICS) {
    const value = metrics[metric as keyof CVSS4Metrics];
    if (value !== undefined && value !== 'X') {
      parts.push(`${metric}:${value}`);
    }
  }

  return parts.join('/');
}

/**
 * Parse CVSS 4.0 vector string into metrics
 */
export function parseVectorString(vectorString: string): CVSS4Metrics {
  if (!vectorString.startsWith('CVSS:4.0/')) {
    throw new Error('Invalid CVSS 4.0 vector string: must start with CVSS:4.0/');
  }

  const metricsString = vectorString.substring('CVSS:4.0/'.length);
  const pairs = metricsString.split('/');

  const metrics: Partial<CVSS4Metrics> = {};

  for (const pair of pairs) {
    const [key, value] = pair.split(':');
    if (key && value) {
      (metrics as any)[key] = value;
    }
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

/**
 * Get effective metric value (use modified if set, otherwise base)
 */
function getEffectiveValue(
  metrics: CVSS4Metrics,
  baseMetric: string,
  modifiedMetric?: string
): string {
  if (modifiedMetric) {
    const modValue = (metrics as any)[modifiedMetric];
    if (modValue && modValue !== 'X') {
      return modValue;
    }
  }
  return (metrics as any)[baseMetric];
}

/**
 * Compute equivalence class 1 (Exploitability)
 * Based on AV, PR, UI
 */
function computeEQ1(metrics: CVSS4Metrics): number {
  const av = getEffectiveValue(metrics, 'AV', 'MAV');
  const pr = getEffectiveValue(metrics, 'PR', 'MPR');
  const ui = getEffectiveValue(metrics, 'UI', 'MUI');

  // EQ1 = 0: AV:N AND PR:N AND UI:N
  if (av === 'N' && pr === 'N' && ui === 'N') {
    return 0;
  }

  // EQ1 = 1: Not (AV:N AND PR:N AND UI:N) AND NOT (AV:P OR PR:H OR UI:A)
  if (!(av === 'P' || pr === 'H' || ui === 'A')) {
    return 1;
  }

  // EQ1 = 2: AV:P OR PR:H OR UI:A
  return 2;
}

/**
 * Compute equivalence class 2 (Complexity)
 * Based on AC, AT
 */
function computeEQ2(metrics: CVSS4Metrics): number {
  const ac = getEffectiveValue(metrics, 'AC', 'MAC');
  const at = getEffectiveValue(metrics, 'AT', 'MAT');

  // EQ2 = 0: AC:L AND AT:N
  if (ac === 'L' && at === 'N') {
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
  const vc = getEffectiveValue(metrics, 'VC', 'MVC');
  const vi = getEffectiveValue(metrics, 'VI', 'MVI');
  const va = getEffectiveValue(metrics, 'VA', 'MVA');

  // EQ3 = 0: VC:H AND VI:H
  if (vc === 'H' && vi === 'H') {
    return 0;
  }

  // EQ3 = 1: NOT (VC:H AND VI:H) AND (VC:H OR VI:H OR VA:H)
  if (vc === 'H' || vi === 'H' || va === 'H') {
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
  const msi = metrics.MSI || 'X';
  const msa = metrics.MSA || 'X';
  const sc = getEffectiveValue(metrics, 'SC', 'MSC');
  const si = msi !== 'X' ? msi : metrics.SI;
  const sa = msa !== 'X' ? msa : metrics.SA;

  // EQ4 = 0: MSI:S OR MSA:S
  if (msi === 'S' || msa === 'S') {
    return 0;
  }

  // EQ4 = 1: NOT (MSI:S OR MSA:S) AND (SC:H OR SI:H OR SA:H)
  if (sc === 'H' || si === 'H' || sa === 'H') {
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
  // Default to 'A' (Attacked) if not defined - worst case assumption
  const e = metrics.E || 'A';

  if (e === 'A' || e === 'X') {
    return 0;
  }
  if (e === 'P') {
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
  // Default security requirements to High if not defined
  const cr = metrics.CR || 'H';
  const ir = metrics.IR || 'H';
  const ar = metrics.AR || 'H';

  const vc = getEffectiveValue(metrics, 'VC', 'MVC');
  const vi = getEffectiveValue(metrics, 'VI', 'MVI');
  const va = getEffectiveValue(metrics, 'VA', 'MVA');

  // EQ6 = 0: (CR:H AND VC:H) OR (IR:H AND VI:H) OR (AR:H AND VA:H)
  if (
    (cr === 'H' && vc === 'H') ||
    (ir === 'H' && vi === 'H') ||
    (ar === 'H' && va === 'H')
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
  const vc = getEffectiveValue(metrics, 'VC', 'MVC');
  const vi = getEffectiveValue(metrics, 'VI', 'MVI');
  const va = getEffectiveValue(metrics, 'VA', 'MVA');
  const sc = getEffectiveValue(metrics, 'SC', 'MSC');
  const si = metrics.MSI !== 'X' && metrics.MSI ? metrics.MSI : metrics.SI;
  const sa = metrics.MSA !== 'X' && metrics.MSA ? metrics.MSA : metrics.SA;

  return vc === 'N' && vi === 'N' && va === 'N' && sc === 'N' && si === 'N' && sa === 'N';
}

/**
 * Get the severity distance for a specific metric
 */
function getMetricDistance(metrics: CVSS4Metrics, metric: string): number {
  const levels = METRIC_LEVELS[metric];
  if (!levels) return 0;

  let value: string;

  // Handle modified metrics
  const modifiedMetric = 'M' + metric;
  if ((metrics as any)[modifiedMetric] && (metrics as any)[modifiedMetric] !== 'X') {
    value = (metrics as any)[modifiedMetric];
  } else {
    value = (metrics as any)[metric];
  }

  // Handle special case for E metric default
  if (metric === 'E' && (!value || value === 'X')) {
    value = 'A';
  }

  // Handle security requirements default
  if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && (!value || value === 'X')) {
    value = 'H';
  }

  return levels[value] || 0;
}

/**
 * Get the next lower MacroVector score for interpolation
 */
function getNextLowerScore(macroVector: string, position: number): number | null {
  const digits = macroVector.split('').map(Number);
  digits[position]++;
  const nextMacroVector = digits.join('');

  return MACROVECTOR_LOOKUP[nextMacroVector] ?? null;
}

/**
 * Calculate the interpolated CVSS score
 */
function interpolateScore(metrics: CVSS4Metrics, macroVector: string, baseScore: number): number {
  const eq1 = parseInt(macroVector[0]);
  const eq2 = parseInt(macroVector[1]);
  const eq3 = parseInt(macroVector[2]);
  const eq4 = parseInt(macroVector[3]);
  const eq5 = parseInt(macroVector[4]);
  const eq6 = parseInt(macroVector[5]);

  // Calculate severity distances for each EQ
  let meanDistance = 0;
  let eqCount = 0;

  // EQ1 distance
  const eq1NextLower = getNextLowerScore(macroVector, 0);
  if (eq1NextLower !== null) {
    const msd = baseScore - eq1NextLower;
    const maxDepth = (MAX_SEVERITY.eq1 as Record<number, number>)[eq1] || 1;
    const avDist = getMetricDistance(metrics, 'AV');
    const prDist = getMetricDistance(metrics, 'PR');
    const uiDist = getMetricDistance(metrics, 'UI');
    const severityDist = avDist + prDist + uiDist;
    const normalizedDist = severityDist / (maxDepth * STEP);
    meanDistance += msd * normalizedDist;
    eqCount++;
  }

  // EQ2 distance
  const eq2NextLower = getNextLowerScore(macroVector, 1);
  if (eq2NextLower !== null) {
    const msd = baseScore - eq2NextLower;
    const maxDepth = (MAX_SEVERITY.eq2 as Record<number, number>)[eq2] || 1;
    const acDist = getMetricDistance(metrics, 'AC');
    const atDist = getMetricDistance(metrics, 'AT');
    const severityDist = acDist + atDist;
    const normalizedDist = severityDist / (maxDepth * STEP);
    meanDistance += msd * normalizedDist;
    eqCount++;
  }

  // EQ3+EQ6 combined distance
  const eq3eq6MaxSeverity = MAX_SEVERITY.eq3eq6 as Record<number, Record<number, number>>;
  if (eq3eq6MaxSeverity[eq3] && eq3eq6MaxSeverity[eq3][eq6] !== undefined) {
    const eq3NextLower = getNextLowerScore(macroVector, 2);
    if (eq3NextLower !== null) {
      const msd = baseScore - eq3NextLower;
      const maxDepth = eq3eq6MaxSeverity[eq3][eq6] || 1;
      const vcDist = getMetricDistance(metrics, 'VC');
      const viDist = getMetricDistance(metrics, 'VI');
      const vaDist = getMetricDistance(metrics, 'VA');
      const crDist = getMetricDistance(metrics, 'CR');
      const irDist = getMetricDistance(metrics, 'IR');
      const arDist = getMetricDistance(metrics, 'AR');
      const severityDist = vcDist + viDist + vaDist + crDist + irDist + arDist;
      const normalizedDist = severityDist / (maxDepth * STEP);
      meanDistance += msd * normalizedDist;
      eqCount++;
    }
  }

  // EQ4 distance
  const eq4NextLower = getNextLowerScore(macroVector, 3);
  if (eq4NextLower !== null) {
    const msd = baseScore - eq4NextLower;
    const maxDepth = (MAX_SEVERITY.eq4 as Record<number, number>)[eq4] || 1;
    const scDist = getMetricDistance(metrics, 'SC');
    const siDist = getMetricDistance(metrics, 'SI');
    const saDist = getMetricDistance(metrics, 'SA');
    const severityDist = scDist + siDist + saDist;
    const normalizedDist = severityDist / (maxDepth * STEP);
    meanDistance += msd * normalizedDist;
    eqCount++;
  }

  // EQ5 distance
  const eq5NextLower = getNextLowerScore(macroVector, 4);
  if (eq5NextLower !== null) {
    const msd = baseScore - eq5NextLower;
    const maxDepth = (MAX_SEVERITY.eq5 as Record<number, number>)[eq5] || 1;
    const eDist = getMetricDistance(metrics, 'E');
    const normalizedDist = eDist / (maxDepth * STEP);
    meanDistance += msd * normalizedDist;
    eqCount++;
  }

  // Calculate final score
  const avgDistance = eqCount > 0 ? meanDistance / eqCount : 0;
  let finalScore = baseScore - avgDistance;

  // Clamp to 0-10 and round to 1 decimal place
  finalScore = Math.max(0, Math.min(10, finalScore));
  finalScore = Math.round(finalScore * 10) / 10;

  return finalScore;
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
      severity: 'NONE',
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
  const hasThreat = metrics.E !== undefined && metrics.E !== 'X';
  const hasEnvironmental =
    (metrics.CR !== undefined && metrics.CR !== 'X') ||
    (metrics.IR !== undefined && metrics.IR !== 'X') ||
    (metrics.AR !== undefined && metrics.AR !== 'X') ||
    (metrics.MAV !== undefined && metrics.MAV !== 'X') ||
    (metrics.MAC !== undefined && metrics.MAC !== 'X') ||
    (metrics.MAT !== undefined && metrics.MAT !== 'X') ||
    (metrics.MPR !== undefined && metrics.MPR !== 'X') ||
    (metrics.MUI !== undefined && metrics.MUI !== 'X') ||
    (metrics.MVC !== undefined && metrics.MVC !== 'X') ||
    (metrics.MVI !== undefined && metrics.MVI !== 'X') ||
    (metrics.MVA !== undefined && metrics.MVA !== 'X') ||
    (metrics.MSC !== undefined && metrics.MSC !== 'X') ||
    (metrics.MSI !== undefined && metrics.MSI !== 'X') ||
    (metrics.MSA !== undefined && metrics.MSA !== 'X');

  if (hasThreat && hasEnvironmental) return 'CVSS-BTE';
  if (hasEnvironmental) return 'CVSS-BE';
  if (hasThreat) return 'CVSS-BT';
  return 'CVSS-B';
}

// =============================================================================
// Validation
// =============================================================================

/**
 * Validate that all required base metrics are present
 */
export function validateMetrics(metrics: Partial<CVSS4Metrics>): metrics is CVSS4Metrics {
  const requiredMetrics = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
  for (const metric of requiredMetrics) {
    if (!(metric in metrics) || (metrics as any)[metric] === undefined) {
      return false;
    }
  }
  return true;
}
