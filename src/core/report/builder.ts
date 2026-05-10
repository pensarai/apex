import type { Finding } from "../agents/offSecAgent";
import { type PentestReport, REPORT_VERSION } from "./schemas";

export interface ReportContext {
  target: string;
  model: string;
  sessionId: string;
  mode: "blackbox" | "whitebox" | "targeted";
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export function buildPentestReport(
  findings: Finding[],
  context: ReportContext,
): PentestReport {
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    bySeverity[f.severity]++;
  }

  return {
    version: REPORT_VERSION,
    metadata: {
      target: context.target,
      model: context.model,
      timestamp: new Date().toISOString(),
      sessionId: context.sessionId,
      mode: context.mode,
    },
    summary: {
      totalFindings: findings.length,
      bySeverity,
    },
    findings: sorted.map((f) => ({
      title: f.title,
      severity: f.severity,
      description: f.description,
      impact: f.impact,
      evidence: f.evidence,
      endpoint: f.endpoint,
      pocPath: f.pocPath,
      remediation: f.remediation,
      references: f.references,
      cwes: f.cwes,
      rootCauseGroup: f.rootCauseGroup,
      relatedFindings: f.relatedFindings,
      evidenceFiles: f.evidenceFiles,
    })),
  };
}
