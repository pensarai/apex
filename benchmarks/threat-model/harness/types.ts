/**
 * Threat Model Benchmark — Shared Types & Ground Truth Normalization
 *
 * The 10 test applications have non-uniform ground-truth.json schemas.
 * This module defines a single canonical form and a normalizer that maps
 * every variant to it. All downstream code uses only the canonical types.
 */

import type { AIModel } from "../../../src/core/ai/ai";
import type { AIAuthConfig } from "../../../src/core/ai/utils";

// ---------------------------------------------------------------------------
// Canonical Ground Truth
// ---------------------------------------------------------------------------

export interface CanonicalGroundTruth {
  id: string;
  name: string;
  description?: string;
  benchmarkType?: string; // e.g. "prompt_injection_resistance", "false_positive_resistance"

  stack?: { primary: string; frameworks: string[]; databases: string[] };
  metrics?: { files: number; loc: number; services: number };

  expectedIdentity: {
    type: string;
    domain: string;
    name?: string;
    repoType?: string;
    languages: string[];
    frameworks: string[];
    databases: string[];
    packageManagers: string[];
    users: string[];
    infrastructure: string[];
    techStack: string[];
  };

  features: CanonicalFeature[];
  trustBoundaries: CanonicalTrustBoundary[];
  securityControls: CanonicalSecurityControl[];
  plantedVulnerabilities: CanonicalVulnerability[];
  falsePositiveTraps: CanonicalFalsePositiveTrap[];

  expectedAttackerProfiles: CanonicalAttackerProfileExpectation;
  expectedAttackPaths: CanonicalAttackPathExpectation;

  // Optional app-specific fields
  deployment?: Record<string, unknown>;
  adversarialInjections?: CanonicalAdversarialInjection[];
  documentationClaims?: { falseClaims: string[] };
  scoringOverrides?: { weights: Record<string, number> };
  systemicVulnerabilityPatterns?: CanonicalSystemicPattern[];
}

export interface CanonicalFeature {
  id: string;
  name: string;
  description: string;
  entryPoints: string[];
}

export interface CanonicalTrustBoundary {
  id?: string;
  name: string;
  description: string;
  from?: string;
  to?: string;
}

export interface CanonicalSecurityControl {
  id: string;
  name: string;
  type?: string;
  effectiveness: string;
  description: string;
  file: string | null;
  appliedTo: string[];
  limitations: string[];
}

export interface CanonicalVulnerability {
  id: string;
  name: string;
  severity: string;
  cwe?: string;
  owasp?: string;
  category?: string;
  subcategory?: string;
  files: Array<{
    path: string;
    lineStart?: number;
    lineEnd?: number;
    role?: string;
  }>;
  description: string;
  attackScenario?: string;
  rootCause?: string;
  expectedInAttackPaths?: boolean;
  isSystemic?: boolean;
  patternRef?: string;
  adversarialComment?: string;
  detectionNotes?: string;
}

export interface CanonicalFalsePositiveTrap {
  id: string;
  name: string;
  file: string;
  lineStart?: number;
  lineEnd?: number;
  pattern?: string;
  whySafe: string;
  expectedNaiveClassification?: string;
  correctClassification: string;
  shouldNotFlagAs?: string;
  trapMechanism?: string;
}

export interface CanonicalAttackerProfileExpectation {
  // Constraint-based form (TM-APP-001, 002, 003, 004)
  min?: number;
  max?: number;
  mustIncludeInsider?: boolean;
  examples?: string[];
  // Enumerated form (TM-APP-005, 006, 008, 009, 010)
  profiles?: Array<{
    name: string;
    description?: string;
    relevantVulns?: string[];
  }>;
}

export interface CanonicalAttackPathExpectation {
  min?: number;
  max?: number;
  mustInclude: string[];
  validAdditionalPaths?: string[];
}

export interface CanonicalAdversarialInjection {
  id: string;
  location: string;
  type: string;
  claim: string;
  reality: string;
  shouldIgnore: boolean;
}

export interface CanonicalSystemicPattern {
  id: string;
  title: string;
  severity: string;
  instanceCount: number;
  affectedFiles: string[];
  rootCause: string;
  description: string;
  evaluationGuidance?: string;
}

// ---------------------------------------------------------------------------
// Parsed Threat Model (from markdown output)
// ---------------------------------------------------------------------------

export interface ParsedThreatModel {
  raw: string;
  metadata: {
    generated?: string;
    codebase?: string;
    type?: string;
    domain?: string;
    repoType?: string;
    packageManager?: string;
    description?: string;
    users?: string;
  };
  features: ParsedFeature[];
  trustBoundaries: ParsedTrustBoundary[];
  attackerProfiles: ParsedAttackerProfile[];
  deploymentModel: string;
  components: ParsedComponent[];
  dataFlows: ParsedDataFlow[];
  securityControls: ParsedSecurityControl[];
  attackPaths: ParsedAttackPath[];
  summary: {
    components?: number;
    dataFlows?: number;
    attackPaths?: number;
    bySeverity: Record<string, number>;
  };
  /** Which top-level ## sections were found */
  sectionsFound: string[];
}

export interface ParsedFeature {
  name: string;
  securityRelevance: string;
  privilegedOps: string;
  dataHandled: string;
}

export interface ParsedTrustBoundary {
  name: string;
  description: string;
  inputSources?: string;
  crossesTo?: string;
}

export interface ParsedAttackerProfile {
  name: string;
  description: string;
  skillLevel?: string;
  controls: string[];
  goals: string[];
}

export interface ParsedComponent {
  id: string;
  name: string;
  type: string;
  technology: string;
  trustBoundary: string;
}

export interface ParsedDataFlow {
  id: string;
  from: string;
  to: string;
  protocol: string;
  dataClassification: string;
  authenticated: string;
  encrypted: string;
}

export interface ParsedSecurityControl {
  id: string;
  name: string;
  type: string;
  effectiveness: string;
  scope: string;
  implementation: string;
  gaps: string;
}

export interface ParsedAttackPath {
  id: string;
  title: string;
  severity: string;
  attackerProfile: string;
  entryPoint: string;
  affectedFeatures: string;
  mechanism: string[];
  impact: string;
  preconditions: string[];
  existingControls: string[];
  controlGaps: string[];
  pentestGuidance: string;
  /** Whether all expected subsections were present */
  subsectionsPresent: {
    mechanism: boolean;
    impact: boolean;
    preconditions: boolean;
    existingControls: boolean;
    controlGaps: boolean;
    pentestGuidance: boolean;
  };
}

// ---------------------------------------------------------------------------
// Behavioral Metrics (from trace)
// ---------------------------------------------------------------------------

export interface BehavioralMetrics {
  totalSteps: number;
  wallClockMs: number;
  filesRead: number;
  sourceFilesRead: number;
  grepCalls: number;
  shellCommands: number;
  completionSuccess: boolean;
}

export interface ToolCallRecord {
  name: string;
  args: Record<string, unknown>;
  timestamp: number;
  subagentId?: string;
}

// ---------------------------------------------------------------------------
// Scores
// ---------------------------------------------------------------------------

export interface StructuralScore {
  score: number;
  checks: Record<string, number>;
}

export interface GroundingScore {
  score: number;
  checks: Record<string, { score: number; found: number; total: number }>;
}

export interface AntiPatternScore {
  score: number;
  checks: Record<string, number>;
}

export interface DiscoveryScore {
  score: number;
  featureRecall: number;
  controlRecall: number;
  boundaryRecall: number;
  componentRecall: number;
  vulnerabilityRecall: number;
  falsePositiveRate: number;
  missedVulnerabilities: string[];
  adversarialResistance?: number;
}

export interface AttackPathJudgeScore {
  score: number;
  perPath: Array<{
    pathId: string;
    specificity: number;
    mechanismQuality: number;
    severityCalibration: number;
    pentestGuidance: number;
    impactConcreteness: number;
    controlAnalysis: number;
  }>;
}

export interface EffectivenessScore {
  score: number;
  coverageBreadth: number;
  attackerProfileRealism: number;
  architectureAccuracy: number;
  securityPostureAssessment: number;
  pentestReadiness: number;
  trustBoundaryQuality: number;
}

export interface AppScorecard {
  appId: string;
  status: "completed" | "failed" | "timeout";
  overall: number;
  structural: StructuralScore | null;
  grounding: GroundingScore | null;
  antipattern: AntiPatternScore | null;
  discovery: DiscoveryScore | null;
  attackPathDepth: AttackPathJudgeScore | null;
  effectiveness: EffectivenessScore | null;
  behavioral: BehavioralMetrics;
  error?: string;
}

export interface AppResult {
  appId: string;
  scorecard: AppScorecard;
  trace: ToolCallRecord[];
}

export interface HeadlineMetrics {
  overallScore: number;
  vulnerabilityRecall: number;
  falsePositiveRate: number;
  groundingScore: number;
  totalCostUsd: number;
}

export interface SuiteResult {
  runId: string;
  model: string;
  timestamp: string;
  config: {
    apps: string[];
    fast: boolean;
    repeats: number;
  };
  headline: HeadlineMetrics;
  perApp: Record<string, AppScorecard>;
  regression?: RegressionResult;
}

export interface RegressionResult {
  previousRunId: string;
  overallDelta: number;
  significantChanges: Array<{
    metric: string;
    app: string;
    delta: number;
    direction: "improvement" | "regression";
  }>;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface BenchmarkConfig {
  apps: string[];
  model: AIModel;
  judgeModel: AIModel;
  repeats: number;
  compareWith?: string;
  fast: boolean;
  appsDir: string;
  resultsDir: string;
  concurrency: number;
  timeout: number;
  authConfig?: AIAuthConfig;
}

// ---------------------------------------------------------------------------
// Ground Truth Normalization
// ---------------------------------------------------------------------------

/* eslint-disable @typescript-eslint/no-explicit-any */

function str(val: unknown): string {
  return typeof val === "string" ? val : "";
}

function strArr(val: unknown): string[] {
  if (Array.isArray(val)) return val.filter((v) => typeof v === "string");
  if (typeof val === "string") return [val];
  return [];
}

function num(val: unknown): number | undefined {
  return typeof val === "number" ? val : undefined;
}

function normalizeFeatures(raw: any[]): CanonicalFeature[] {
  return raw.map((f, i) => {
    if (typeof f === "string") {
      return {
        id: `feat-${i + 1}`,
        name: f,
        description: f,
        entryPoints: [],
      };
    }
    return {
      id: str(f.id) || `feat-${i + 1}`,
      name: str(f.name),
      description: str(f.description),
      entryPoints: strArr(f.entry_points),
    };
  });
}

function normalizeTrustBoundaries(raw: any[]): CanonicalTrustBoundary[] {
  return raw.map((b, i) => ({
    id: str(b.id) || undefined,
    name: str(b.name) || `boundary-${i + 1}`,
    description: str(b.description),
    from: str(b.from) || undefined,
    to: str(b.to) || undefined,
  }));
}

function normalizeSecurityControls(raw: any[]): CanonicalSecurityControl[] {
  return raw.map((c) => ({
    id: str(c.id),
    name: str(c.name),
    type: str(c.type) || undefined,
    effectiveness: str(c.effectiveness),
    description: str(c.description),
    file: c.file ?? null,
    appliedTo: strArr(c.applied_to),
    limitations: strArr(c.limitations),
  }));
}

function normalizeVulnerability(v: any): CanonicalVulnerability {
  // Normalize file references into a unified files[] array
  const files: CanonicalVulnerability["files"] = [];

  if (Array.isArray(v.files)) {
    // Multi-file format (TM-APP-002, 003)
    for (const f of v.files) {
      files.push({
        path: str(f.path),
        lineStart: num(f.line_start),
        lineEnd: num(f.line_end),
        role: str(f.role) || undefined,
      });
    }
  } else if (v.file) {
    // Single-file format. line_start/line_end (001,004,007,009,010) or start_line/end_line (005)
    files.push({
      path: str(v.file),
      lineStart: num(v.line_start) ?? num(v.start_line),
      lineEnd: num(v.line_end) ?? num(v.end_line),
    });
  }

  // Merge secondary_locations (TM-APP-007 systemic vulns)
  if (Array.isArray(v.secondary_locations)) {
    for (const loc of v.secondary_locations) {
      files.push({
        path: str(loc.file),
        lineStart: num(loc.line_start),
        lineEnd: num(loc.line_end),
        role: "secondary",
      });
    }
  }

  return {
    id: str(v.id),
    name: str(v.name) || str(v.title),
    severity: str(v.severity),
    cwe: str(v.cwe) || undefined,
    owasp: str(v.owasp) || undefined,
    category: str(v.category) || undefined,
    subcategory: str(v.subcategory) || undefined,
    files,
    description: str(v.description),
    attackScenario: str(v.attack_scenario) || str(v.attack_vector) || undefined,
    rootCause: str(v.root_cause) || undefined,
    expectedInAttackPaths: v.expected_in_attack_paths ?? undefined,
    isSystemic: v.is_systemic ?? undefined,
    patternRef: str(v.pattern_ref) || undefined,
    adversarialComment: str(v.adversarial_comment) || undefined,
    detectionNotes: str(v.detection_notes) || undefined,
  };
}

function normalizeFalsePositiveTraps(raw: any[]): CanonicalFalsePositiveTrap[] {
  return raw.map((fp) => ({
    id: str(fp.id),
    name: str(fp.name) || str(fp.title),
    file: str(fp.file),
    lineStart: num(fp.line) ?? num(fp.line_start),
    lineEnd: num(fp.line_end),
    pattern: str(fp.pattern) || str(fp.trap_mechanism) || undefined,
    whySafe: str(fp.why_safe),
    expectedNaiveClassification:
      str(fp.expected_naive_classification) || undefined,
    correctClassification: str(fp.correct_classification) || "safe",
    shouldNotFlagAs: str(fp.should_NOT_flag_as) || undefined,
    trapMechanism: str(fp.trap_mechanism) || undefined,
  }));
}

function normalizeAttackerProfiles(raw: any): CanonicalAttackerProfileExpectation {
  if (Array.isArray(raw)) {
    // Enumerated form (TM-APP-005, 006, 008, 009, 010)
    return {
      profiles: raw.map((p: any) => ({
        name: str(p.name),
        description: str(p.description) || undefined,
        relevantVulns: strArr(p.relevant_vulns),
      })),
    };
  }
  // Constraint-based form (TM-APP-001, 002, 003, 004)
  return {
    min: num(raw.min),
    max: num(raw.max),
    mustIncludeInsider: raw.must_include_insider ?? undefined,
    examples: strArr(raw.examples),
  };
}

function normalizeAttackPaths(raw: any): CanonicalAttackPathExpectation {
  return {
    min: num(raw.min),
    max: num(raw.max),
    mustInclude: strArr(raw.must_include),
    validAdditionalPaths:
      strArr(raw.valid_additional_paths ?? raw.additional_expected) || undefined,
  };
}

function normalizeAdversarialInjections(
  raw: any[],
): CanonicalAdversarialInjection[] {
  return raw.map((a) => ({
    id: str(a.id),
    location: str(a.location),
    type: str(a.type),
    claim: str(a.claim),
    reality: str(a.reality),
    shouldIgnore: a.should_ignore ?? true,
  }));
}

function normalizeSystemicPatterns(raw: any[]): CanonicalSystemicPattern[] {
  return raw.map((p) => ({
    id: str(p.id),
    title: str(p.title),
    severity: str(p.severity),
    instanceCount: p.instance_count ?? 0,
    affectedFiles: strArr(p.affected_files),
    rootCause: str(p.root_cause),
    description: str(p.description),
    evaluationGuidance: str(p.evaluation_guidance) || undefined,
  }));
}

/**
 * Normalize any ground-truth.json variant into the canonical form.
 * This is the ONLY place that knows about schema differences between apps.
 */
export function normalizeGroundTruth(raw: any): CanonicalGroundTruth {
  const id = str(raw.id) || str(raw.benchmark_id);
  const name = str(raw.name) || str(raw.benchmark_name);
  const ei = raw.expected_identity ?? {};

  // Normalize identity — handle string vs array variants
  const languages = strArr(ei.languages ?? ei.language);
  const frameworks = strArr(ei.frameworks ?? ei.framework);
  const databases = strArr(ei.databases ?? ei.database);
  const packageManagers = strArr(
    ei.package_managers ?? ei.package_manager,
  );
  const users = strArr(ei.users);
  const infrastructure = strArr(ei.infrastructure);
  const techStack = strArr(ei.tech_stack);

  // Scoring overrides
  let scoringOverrides: { weights: Record<string, number> } | undefined;
  if (raw.scoring?.weights) {
    scoringOverrides = { weights: raw.scoring.weights };
  }

  return {
    id,
    name,
    description: str(raw.description) || undefined,
    benchmarkType: str(raw.benchmark_type) || undefined,

    stack: raw.stack
      ? {
          primary: str(raw.stack.primary),
          frameworks: strArr(raw.stack.frameworks),
          databases: strArr(raw.stack.databases),
        }
      : undefined,

    metrics: raw.metrics
      ? {
          files: raw.metrics.files ?? 0,
          loc: raw.metrics.loc ?? 0,
          services: raw.metrics.services ?? 0,
        }
      : undefined,

    expectedIdentity: {
      type: str(ei.type),
      domain: str(ei.domain),
      name: str(ei.name) || undefined,
      repoType: str(ei.repo_type) || undefined,
      languages,
      frameworks,
      databases,
      packageManagers,
      users,
      infrastructure,
      techStack,
    },

    features: normalizeFeatures(raw.features ?? []),
    trustBoundaries: normalizeTrustBoundaries(raw.trust_boundaries ?? []),
    securityControls: normalizeSecurityControls(raw.security_controls ?? []),
    plantedVulnerabilities: (raw.planted_vulnerabilities ?? []).map(
      normalizeVulnerability,
    ),
    falsePositiveTraps: normalizeFalsePositiveTraps(
      raw.false_positive_traps ?? [],
    ),

    expectedAttackerProfiles: normalizeAttackerProfiles(
      raw.expected_attacker_profiles ?? {},
    ),
    expectedAttackPaths: normalizeAttackPaths(raw.expected_attack_paths ?? {}),

    deployment: raw.deployment ?? undefined,
    adversarialInjections: raw.adversarial_injections
      ? normalizeAdversarialInjections(raw.adversarial_injections)
      : undefined,
    documentationClaims: raw.documentation_claims
      ? { falseClaims: strArr(raw.documentation_claims.false_claims) }
      : undefined,
    scoringOverrides,
    systemicVulnerabilityPatterns: raw.systemic_vulnerability_patterns
      ? normalizeSystemicPatterns(raw.systemic_vulnerability_patterns)
      : undefined,
  };
}
