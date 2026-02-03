import { z } from "zod";

export const VulnerabilityClassSchema = z.enum([
  "sql_injection",
  "nosql_injection",
  "xss",
  "command_injection",
  "ssti",
  "path_traversal",
  "ssrf",
  "idor",
  "authentication_bypass",
  "jwt_vulnerabilities",
  "deserialization",
  "xxe",
  "crypto",
  "business_logic",
  "generic",
]);

export type VulnerabilityClass = z.infer<typeof VulnerabilityClassSchema>;

export const SubAgentConfigSchema = z.object({
  id: z.string(),
  endpoint: z.string(),
  vulnerabilityClass: VulnerabilityClassSchema,
  context: z.record(z.string(), z.any()).optional(),
  priority: z.enum(["critical", "high", "medium", "low"]).default("medium"),
  whiteboxMode: z.boolean().default(false),
  sourceCodePath: z.string().optional(),
});

export type SubAgentConfig = z.infer<typeof SubAgentConfigSchema>;

export const SubAgentManifestSchema = z.object({
  sessionId: z.string(),
  createdAt: z.string(),
  attackSurfacePath: z.string(),
  whiteboxMode: z.boolean(),
  subagents: z.array(SubAgentConfigSchema),
});

export type SubAgentManifest = z.infer<typeof SubAgentManifestSchema>;

export const PlanPhaseSchema = z.object({
  name: z.string(),
  description: z.string(),
  techniques: z.array(z.string()),
  completed: z.boolean().default(false),
  notes: z.string().optional(),
});

export type PlanPhase = z.infer<typeof PlanPhaseSchema>;

export const AttackPlanSchema = z.object({
  subagentId: z.string(),
  endpoint: z.string(),
  vulnerabilityClass: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
  summary: z.string(),
  phases: z.array(PlanPhaseSchema),
  contextGathered: z.record(z.string(), z.any()).optional(),
  notes: z.array(z.string()).default([]),
});

export type AttackPlan = z.infer<typeof AttackPlanSchema>;

export const TieredIndicatorSchema = z.union([
  z.string(),
  z.object({
    indicator: z.string(),
    tier: z.enum(["high", "medium", "low"]),
  }),
]);

export type TieredIndicator = z.infer<typeof TieredIndicatorSchema>;

export const VerificationCriteriaSchema = z.object({
  subagentId: z.string(),
  vulnerabilityClass: z.string(),
  createdAt: z.string(),
  successIndicators: z.array(TieredIndicatorSchema),
  failureIndicators: z.array(z.string()),
  verificationSteps: z.array(
    z.object({
      description: z.string(),
      expectedOutcome: z.string(),
      method: z.enum(["response_contains", "status_code", "timing", "script", "manual"]),
      value: z.string().optional(),
    })
  ),
  minimumConfidence: z.number().default(80),
});

export type VerificationCriteria = z.infer<typeof VerificationCriteriaSchema>;

export const FindingSchema = z.object({
  id: z.string(),
  subagentId: z.string(),
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  vulnerabilityClass: z.string(),
  endpoint: z.string(),
  description: z.string(),
  impact: z.string(),
  evidence: z.string(),
  pocPath: z.string(),
  remediation: z.string(),
  verificationPassed: z.boolean(),
  createdAt: z.string(),
});

export type Finding = z.infer<typeof FindingSchema>;

export interface SubAgentSession {
  id: string;
  sessionId: string;
  config: SubAgentConfig;
  rootPath: string;
  planPath: string;
  verificationPath: string;
  findingsPath: string;
  scriptsPath: string;
  logsPath: string;
  guidancePath: string;
}

export interface InitAgentResult {
  success: boolean;
  plan: AttackPlan;
  verificationCriteria: VerificationCriteria;
  error?: string;
}

export interface AttackAgentResult {
  success: boolean;
  findings: Finding[];
  summary: string;
  error?: string;
}

export interface SubAgentError {
  phase: 'init' | 'attack' | 'timeout' | 'unknown';
  message: string;
  timedOut?: boolean;
}

export interface FileAccessConfig {
  /** Directories the agent is allowed to read/write (whitelist) */
  allowedPaths: string[];
  /** Explicitly blocked paths (takes precedence over allowed) */
  blockedPaths: string[];
}
