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
  consolidatedAssociations: number;
  missionProgress: EngagementMissionProgress;
}

export type EngagementMissionProgressStatus =
  | "planned"
  | "queued"
  | "running"
  | "completed"
  | "blocked"
  | "failed";

export interface EngagementMissionProgressItem {
  id: string;
  workerId: string;
  purpose: string;
  status: EngagementMissionProgressStatus;
  canonicalRequirements: number;
  sourceAssociations: number;
  startedAt?: string;
  completedAt?: string;
}

export interface EngagementMissionProgress {
  planningStatus: "pending" | "partial" | "complete";
  total: number;
  completed: number;
  blocked: number;
  failed: number;
  running: number;
  queued: number;
  items: EngagementMissionProgressItem[];
}

export function projectEngagementMissionProgress(
  checkpoint: EngagementCheckpoint,
): EngagementMissionProgress {
  const planningStatus = checkpoint.missions?.planningStatus ?? "pending";
  const items = (checkpoint.missions?.missions ?? []).map((mission) => {
    const missionCoverage = checkpoint.coverage.filter(
      (cell) => cell.missionId === mission.id,
    );
    let status: EngagementMissionProgressStatus = mission.status;
    if (mission.status === "completed") {
      status = missionCoverage.some(
        (cell) => cell.status === "blocked" || cell.status === "needs-lead",
      )
        ? "blocked"
        : "completed";
    }
    return {
      id: mission.id,
      workerId: mission.workerId,
      purpose: mission.purpose,
      status,
      canonicalRequirements:
        mission.requirements?.length ?? mission.coverage.length,
      sourceAssociations: mission.coverage.length,
      startedAt: mission.startedAt,
      completedAt: mission.completedAt,
    };
  });
  const count = (status: EngagementMissionProgressStatus) =>
    items.filter((item) => item.status === status).length;
  return {
    planningStatus,
    total: items.length,
    completed: count("completed"),
    blocked: count("blocked"),
    failed: count("failed"),
    running: count("running"),
    queued: count("planned") + count("queued"),
    items,
  };
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
  const canonicalRequirements =
    checkpoint.missions?.missions.reduce(
      (total, mission) =>
        total + (mission.requirements?.length ?? mission.coverage.length),
      0,
    ) ?? 0;
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
    consolidatedAssociations: Math.max(
      0,
      checkpoint.coverage.length - canonicalRequirements,
    ),
    missionProgress: projectEngagementMissionProgress(checkpoint),
  };
}
