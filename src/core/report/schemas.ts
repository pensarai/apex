import { z } from "zod";
import { AttackPathSchema } from "../../lib/attack-path/types";
import { CweEntrySchema, ValidatedCweEntrySchema } from "../../lib/cwe/types";
import { EvidenceFileEntrySchema } from "../../lib/evidence/types";

export const PentestReportFindingSchema = z.object({
  id: z.string().optional(),
  title: z.string(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  description: z.string(),
  impact: z.string(),
  evidence: z.string(),
  endpoint: z.string(),
  pocPath: z.string(),
  remediation: z.string(),
  references: z.string().optional(),
  cwes: z.array(ValidatedCweEntrySchema.or(CweEntrySchema)).optional(),
  rootCauseGroup: z.string().optional(),
  relatedFindings: z.array(z.string()).optional(),
  rootCauseLead: z.boolean().optional(),
  canonicalFindingId: z.string().optional(),
  evidenceFiles: z.array(EvidenceFileEntrySchema).optional(),
  attackPath: AttackPathSchema.optional(),
});

export const PentestReportChainStepSchema = z.object({
  id: z.string().optional(),
  title: z.string(),
  description: z.string(),
  findingIds: z.array(z.string()),
  capabilityIds: z.array(z.string()),
  impactProofIds: z.array(z.string()).optional(),
  objectiveIds: z.array(z.string()).optional(),
  serviceIds: z.array(z.string()).optional(),
  targetIds: z.array(z.string()).optional(),
  artifactPaths: z.array(z.string()).optional(),
  observationRefs: z.array(z.string()).optional(),
  evidence: z.array(z.string()),
});

export const PentestReportChainSchema = z.object({
  id: z.string(),
  title: z.string(),
  status: z.enum(["impact-proven", "exhausted", "blocked"]),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional(),
  description: z.string(),
  impact: z.string(),
  remediation: z.string().optional(),
  findingIds: z.array(z.string()),
  capabilityIds: z.array(z.string()),
  impactProofIds: z.array(z.string()),
  objectiveIds: z.array(z.string()),
  serviceIds: z.array(z.string()),
  targetIds: z.array(z.string()),
  evidence: z.array(z.string()),
  steps: z.array(PentestReportChainStepSchema),
  evidenceQuality: z.enum(["verified", "legacy-incomplete"]).optional(),
  blocker: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export const PentestReportEngagementSchema = z.object({
  planningStatus: z.enum(["pending", "partial", "complete"]).optional(),
  missions: z.object({
    total: z.number(),
    completed: z.number(),
    failed: z.number(),
    active: z.number(),
  }),
  coverage: z.object({
    total: z.number(),
    impactProven: z.number(),
    exhausted: z.number(),
    blocked: z.number(),
    open: z.number(),
  }),
  chainExplore: z.object({
    status: z.enum([
      "pending",
      "running",
      "impact-proven",
      "exhausted",
      "blocked",
    ]),
    summary: z.string().optional(),
    evidence: z.array(z.string()),
  }),
});

export const PentestReportSchema = z.object({
  version: z.string().regex(/^1\.\d+$/),
  metadata: z.object({
    target: z.string(),
    model: z.string(),
    timestamp: z.string(),
    sessionId: z.string(),
    mode: z.enum(["blackbox", "whitebox", "targeted"]),
  }),
  summary: z.object({
    totalFindings: z.number(),
    bySeverity: z.object({
      CRITICAL: z.number(),
      HIGH: z.number(),
      MEDIUM: z.number(),
      LOW: z.number(),
    }),
  }),
  findings: z.array(PentestReportFindingSchema),
  chains: z.array(PentestReportChainSchema).optional(),
  engagement: PentestReportEngagementSchema.optional(),
});

export const REPORT_VERSION = "1.1";

export type PentestReport = z.infer<typeof PentestReportSchema>;
export type PentestReportFinding = z.infer<typeof PentestReportFindingSchema>;
export type PentestReportChain = z.infer<typeof PentestReportChainSchema>;
