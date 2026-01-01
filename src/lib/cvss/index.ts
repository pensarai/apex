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

// Types
export type {
  AttackVector,
  AttackComplexity,
  AttackRequirements,
  PrivilegesRequired,
  UserInteraction,
  VulnerableConfidentiality,
  VulnerableIntegrity,
  VulnerableAvailability,
  SubsequentConfidentiality,
  SubsequentIntegrity,
  SubsequentAvailability,
  ExploitMaturity,
  SecurityRequirement,
  ModifiedMetric,
  ModifiedSubsequentImpact,
  Safety,
  Automatable,
  Recovery,
  ValueDensity,
  ResponseEffort,
  ProviderUrgency,
  CVSS4BaseMetrics,
  CVSS4ThreatMetrics,
  CVSS4EnvironmentalMetrics,
  CVSS4SupplementalMetrics,
  CVSS4Metrics,
  CVSS4Severity,
  CVSS4ScoreType,
  CVSS4Score,
} from './types';

// Type utilities
export { SEVERITY_RATINGS, getSeverityFromScore } from './types';

// Calculator functions
export {
  calculateCVSS4Score,
  buildVectorString,
  parseVectorString,
  computeMacroVector,
  validateMetrics,
} from './calculator';

// Lookup tables (for advanced usage)
export { MACROVECTOR_LOOKUP, METRIC_LEVELS } from './macrovector-scores';
