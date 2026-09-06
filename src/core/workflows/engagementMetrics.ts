import type { EngagementCheckpoint } from "./engagementState";

export interface EngagementMetrics {
  coverage: {
    total: number;
    tested: number;
    blocked: number;
    untested: number;
  };
  missions: number;
  workers: number;
  obligationsPerMission: number;
  avoidedPerCellWorkers: number;
}

export function summarizeEngagementCheckpoint(
  checkpoint: EngagementCheckpoint,
): EngagementMetrics {
  const tested = checkpoint.coverage.filter(
    (cell) => cell.status === "impact-proven" || cell.status === "exhausted",
  ).length;
  const blocked = checkpoint.coverage.filter(
    (cell) => cell.status === "blocked",
  ).length;
  const missions = checkpoint.missions?.missions.length ?? 0;
  return {
    coverage: {
      total: checkpoint.coverage.length,
      tested,
      blocked,
      untested: checkpoint.coverage.length - tested - blocked,
    },
    missions,
    workers: checkpoint.workers.length,
    obligationsPerMission:
      missions === 0 ? 0 : checkpoint.coverage.length / missions,
    avoidedPerCellWorkers: Math.max(0, checkpoint.coverage.length - missions),
  };
}
