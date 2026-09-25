import type { Finding } from "../agents/offSecAgent";
import { findingReferenceId } from "../findings/registry";
import {
  type PentestReport,
  type PentestReportChain,
  REPORT_VERSION,
} from "./schemas";

export interface ReportContext {
  target: string;
  model: string;
  sessionId: string;
  mode: "blackbox" | "whitebox" | "targeted";
}

export interface ReportEngagementContext {
  chains: PentestReportChain[];
  coverage: Array<{
    status:
      | "pending"
      | "assigned"
      | "running"
      | "needs-lead"
      | "impact-proven"
      | "exhausted"
      | "blocked";
  }>;
  missions?: {
    planningStatus: "pending" | "partial" | "complete";
    missions: Array<{
      status: "planned" | "queued" | "running" | "completed" | "failed";
    }>;
  };
  chainExplore: {
    status: "pending" | "running" | "impact-proven" | "exhausted" | "blocked";
    summary?: string;
    evidence: string[];
  };
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export function buildPentestReport(
  findings: Finding[],
  context: ReportContext,
  engagement?: ReportEngagementContext,
): PentestReport {
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    bySeverity[f.severity]++;
  }

  const missionStatuses = engagement?.missions?.missions ?? [];
  const coverageStatuses = engagement?.coverage ?? [];

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
      id: findingReferenceId(f),
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
      rootCauseLead: f.rootCauseLead,
      evidenceFiles: f.evidenceFiles,
      attackPath: f.attackPath,
    })),
    ...(engagement && {
      chains: engagement.chains,
      engagement: {
        planningStatus: engagement.missions?.planningStatus,
        missions: {
          total: missionStatuses.length,
          completed: missionStatuses.filter(
            (mission) => mission.status === "completed",
          ).length,
          failed: missionStatuses.filter(
            (mission) => mission.status === "failed",
          ).length,
          active: missionStatuses.filter(
            (mission) =>
              mission.status === "planned" ||
              mission.status === "queued" ||
              mission.status === "running",
          ).length,
        },
        coverage: {
          total: coverageStatuses.length,
          impactProven: coverageStatuses.filter(
            (cell) => cell.status === "impact-proven",
          ).length,
          exhausted: coverageStatuses.filter(
            (cell) => cell.status === "exhausted",
          ).length,
          blocked: coverageStatuses.filter((cell) => cell.status === "blocked")
            .length,
          open: coverageStatuses.filter(
            (cell) =>
              cell.status === "pending" ||
              cell.status === "assigned" ||
              cell.status === "running" ||
              cell.status === "needs-lead",
          ).length,
        },
        chainExplore: engagement.chainExplore,
      },
    }),
  };
}
