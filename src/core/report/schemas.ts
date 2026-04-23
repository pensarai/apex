import { z } from "zod";
import { CweEntrySchema, ValidatedCweEntrySchema } from "../../lib/cwe/types";
import { EvidenceFileEntrySchema } from "../../lib/evidence/types";

export const PentestReportFindingSchema = z.object({
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
  evidenceFiles: z.array(EvidenceFileEntrySchema).optional(),
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
});

export const REPORT_VERSION = "1.0";

export type PentestReport = z.infer<typeof PentestReportSchema>;
export type PentestReportFinding = z.infer<typeof PentestReportFindingSchema>;
