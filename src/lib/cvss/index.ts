/**
 * CVSS 4.0 Calculator Module
 *
 * Provides CVSS 4.0 scoring functionality for vulnerability assessment.
 *
 * Usage:
 * ```typescript
 * import { calculateCVSS4Score, parseVectorString } from './lib/cvss';
 *
 * const score = calculateCVSS4Score({
 *   AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
 *   VC: 'H', VI: 'H', VA: 'H',
 *   SC: 'N', SI: 'N', SA: 'N',
 * });
 *
 * console.log(score.score);        // 9.3
 * console.log(score.severity);     // 'CRITICAL'
 * console.log(score.vectorString); // 'CVSS:4.0/AV:N/AC:L/AT:N/...'
 * ```
 */

// Calculator functions
export {
  buildVectorString,
  calculateCVSS4Score,
  computeMacroVector,
  parseVectorString,
  validateMetrics,
} from "./calculator";
// Lookup tables (for advanced usage)
export { MACROVECTOR_LOOKUP, METRIC_LEVELS } from "./macrovector-scores";
// Types
export type {
  AttackComplexity,
  AttackRequirements,
  AttackVector,
  Automatable,
  CVSS4BaseMetrics,
  CVSS4EnvironmentalMetrics,
  CVSS4Metrics,
  CVSS4Score,
  CVSS4ScoreType,
  CVSS4Severity,
  CVSS4SupplementalMetrics,
  CVSS4ThreatMetrics,
  ExploitMaturity,
  ModifiedMetric,
  ModifiedSubsequentImpact,
  PrivilegesRequired,
  ProviderUrgency,
  Recovery,
  ResponseEffort,
  Safety,
  SecurityRequirement,
  SubsequentAvailability,
  SubsequentConfidentiality,
  SubsequentIntegrity,
  UserInteraction,
  ValueDensity,
  VulnerableAvailability,
  VulnerableConfidentiality,
  VulnerableIntegrity,
} from "./types";
// Type utilities
export { getSeverityFromScore, SEVERITY_RATINGS } from "./types";
