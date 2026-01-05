/**
 * CVSS 4.0 Type Definitions
 *
 * Based on FIRST CVSS v4.0 Specification Document
 * https://www.first.org/cvss/v4-0/specification-document
 */

// =============================================================================
// Base Metrics - Exploitability
// =============================================================================

/** Attack Vector (AV) - How the vulnerability can be exploited */
export type AttackVector = 'N' | 'A' | 'L' | 'P';
// N = Network: Remotely exploitable over the internet
// A = Adjacent: Requires shared physical/logical network
// L = Local: Requires local access or social engineering
// P = Physical: Requires physical hardware access

/** Attack Complexity (AC) - Conditions beyond attacker's control */
export type AttackComplexity = 'L' | 'H';
// L = Low: No special conditions needed
// H = High: Requires bypassing security measures or race conditions

/** Attack Requirements (AT) - Prerequisite deployment conditions */
export type AttackRequirements = 'N' | 'P';
// N = None: Attack succeeds under most configurations
// P = Present: Requires specific conditions (race, network injection)

/** Privileges Required (PR) - Attacker's privilege level before exploitation */
export type PrivilegesRequired = 'N' | 'L' | 'H';
// N = None: Unauthenticated attack
// L = Low: Basic user-level privileges
// H = High: Administrative privileges

/** User Interaction (UI) - Human participation required */
export type UserInteraction = 'N' | 'P' | 'A';
// N = None: No user action required
// P = Passive: User visits a page or opens a file
// A = Active: User must click, dismiss warnings, or interact

// =============================================================================
// Base Metrics - Impact (Vulnerable System)
// =============================================================================

/** Confidentiality Impact on Vulnerable System */
export type VulnerableConfidentiality = 'H' | 'L' | 'N';
// H = High: Total loss of confidentiality
// L = Low: Partial or limited impact
// N = None: No impact

/** Integrity Impact on Vulnerable System */
export type VulnerableIntegrity = 'H' | 'L' | 'N';

/** Availability Impact on Vulnerable System */
export type VulnerableAvailability = 'H' | 'L' | 'N';

// =============================================================================
// Base Metrics - Impact (Subsequent System)
// =============================================================================

/** Confidentiality Impact on Subsequent Systems */
export type SubsequentConfidentiality = 'H' | 'L' | 'N';

/** Integrity Impact on Subsequent Systems */
export type SubsequentIntegrity = 'H' | 'L' | 'N';

/** Availability Impact on Subsequent Systems */
export type SubsequentAvailability = 'H' | 'L' | 'N';

// =============================================================================
// Threat Metrics
// =============================================================================

/** Exploit Maturity (E) - Current exploitation state */
export type ExploitMaturity = 'X' | 'A' | 'P' | 'U';
// X = Not Defined: Assumes worst case (Attacked)
// A = Attacked: Active exploitation or public exploit tools
// P = POC: Proof-of-concept available, no active attacks
// U = Unreported: No public PoC or known exploitation

// =============================================================================
// Environmental Metrics - Security Requirements
// =============================================================================

/** Security Requirement level for CIA attributes */
export type SecurityRequirement = 'X' | 'H' | 'M' | 'L';
// X = Not Defined: Assumes High
// H = High: Loss causes catastrophic effects
// M = Medium: Loss causes serious effects
// L = Low: Loss causes limited effects

// =============================================================================
// Environmental Metrics - Modified Base Metrics
// =============================================================================

/** Modified metric type (adds 'X' for Not Defined) */
export type ModifiedMetric<T extends string> = T | 'X';

/** Modified Subsequent System Impact with Safety option */
export type ModifiedSubsequentImpact = 'H' | 'L' | 'N' | 'X' | 'S';
// S = Safety: Human safety impact (IEC 61508)

// =============================================================================
// Supplemental Metrics (Informational only, don't affect score)
// =============================================================================

/** Safety (S) - Human safety impact */
export type Safety = 'X' | 'P' | 'N';
// P = Present: Marginal or worse injuries possible
// N = Negligible: Minor injuries at worst

/** Automatable (AU) - Can exploitation be automated? */
export type Automatable = 'X' | 'Y' | 'N';

/** Recovery (R) - System resilience post-attack */
export type Recovery = 'X' | 'A' | 'U' | 'I';
// A = Automatic: Self-recovery
// U = User: Manual intervention required
// I = Irrecoverable: Permanent service loss

/** Value Density (V) - Resources controllable per exploitation */
export type ValueDensity = 'X' | 'C' | 'D';
// C = Concentrated: Rich-resource systems
// D = Diffuse: Limited resources

/** Response Effort (RE) - Remediation difficulty */
export type ResponseEffort = 'X' | 'L' | 'M' | 'H';

/** Provider Urgency (U) - Vendor severity assessment */
export type ProviderUrgency = 'X' | 'Red' | 'Amber' | 'Green' | 'Clear';

// =============================================================================
// Complete Metrics Interface
// =============================================================================

export interface CVSS4BaseMetrics {
  // Exploitability Metrics (required)
  AV: AttackVector;
  AC: AttackComplexity;
  AT: AttackRequirements;
  PR: PrivilegesRequired;
  UI: UserInteraction;

  // Vulnerable System Impact (required)
  VC: VulnerableConfidentiality;
  VI: VulnerableIntegrity;
  VA: VulnerableAvailability;

  // Subsequent System Impact (required)
  SC: SubsequentConfidentiality;
  SI: SubsequentIntegrity;
  SA: SubsequentAvailability;
}

export interface CVSS4ThreatMetrics {
  E?: ExploitMaturity;
}

export interface CVSS4EnvironmentalMetrics {
  // Security Requirements
  CR?: SecurityRequirement;
  IR?: SecurityRequirement;
  AR?: SecurityRequirement;

  // Modified Base Metrics
  MAV?: ModifiedMetric<AttackVector>;
  MAC?: ModifiedMetric<AttackComplexity>;
  MAT?: ModifiedMetric<AttackRequirements>;
  MPR?: ModifiedMetric<PrivilegesRequired>;
  MUI?: ModifiedMetric<UserInteraction>;
  MVC?: ModifiedMetric<VulnerableConfidentiality>;
  MVI?: ModifiedMetric<VulnerableIntegrity>;
  MVA?: ModifiedMetric<VulnerableAvailability>;
  MSC?: ModifiedMetric<SubsequentConfidentiality>;
  MSI?: ModifiedSubsequentImpact;
  MSA?: ModifiedSubsequentImpact;
}

export interface CVSS4SupplementalMetrics {
  S?: Safety;
  AU?: Automatable;
  R?: Recovery;
  V?: ValueDensity;
  RE?: ResponseEffort;
  U?: ProviderUrgency;
}

/** Complete CVSS 4.0 Metrics */
export interface CVSS4Metrics
  extends CVSS4BaseMetrics,
    CVSS4ThreatMetrics,
    CVSS4EnvironmentalMetrics,
    CVSS4SupplementalMetrics {}

// =============================================================================
// Score Types
// =============================================================================

/** CVSS 4.0 severity ratings */
export type CVSS4Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** Score type nomenclature */
export type CVSS4ScoreType = 'CVSS-B' | 'CVSS-BT' | 'CVSS-BE' | 'CVSS-BTE';

/** Complete CVSS 4.0 Score result */
export interface CVSS4Score {
  /** Numeric score from 0.0 to 10.0 */
  score: number;
  /** Qualitative severity rating */
  severity: CVSS4Severity;
  /** Vector string (e.g., CVSS:4.0/AV:N/AC:L/...) */
  vectorString: string;
  /** All metrics used in calculation */
  metrics: CVSS4Metrics;
  /** Score type based on which metrics were provided */
  scoreType: CVSS4ScoreType;
}

// =============================================================================
// Severity Rating Ranges
// =============================================================================

export const SEVERITY_RATINGS: Record<CVSS4Severity, { min: number; max: number }> = {
  NONE: { min: 0.0, max: 0.0 },
  LOW: { min: 0.1, max: 3.9 },
  MEDIUM: { min: 4.0, max: 6.9 },
  HIGH: { min: 7.0, max: 8.9 },
  CRITICAL: { min: 9.0, max: 10.0 },
};

/** Get severity rating from numeric score */
export function getSeverityFromScore(score: number): CVSS4Severity {
  if (score === 0) return 'NONE';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
}
