import { describe, expect, it } from "vitest";
import {
  projectEngagementMissionProgress,
  summarizeEngagementCheckpoint,
} from "./engagementMetrics";
import type { EngagementCheckpoint } from "./engagementState";

describe("summarizeEngagementCheckpoint", () => {
  it("separates tested, blocked, and untested while measuring grouping", () => {
    const checkpoint = {
      coverage: [
        { status: "exhausted", missionId: "mission-1" },
        { status: "impact-proven", missionId: "mission-1" },
        { status: "blocked", missionId: "mission-2" },
        { status: "running", missionId: "mission-2" },
      ],
      workers: [{}, {}],
      missions: {
        planningStatus: "complete",
        missions: [
          {
            id: "mission-1",
            workerId: "worker-1",
            purpose: "Test shared authorization",
            status: "completed",
            coverage: [{}, {}],
            requirements: [
              {
                id: "owner-boundary",
                coverage: [{}, {}],
              },
            ],
          },
          {
            id: "mission-2",
            workerId: "worker-2",
            purpose: "Test account recovery",
            status: "completed",
            coverage: [{}, {}],
          },
        ],
      },
    } as EngagementCheckpoint;

    expect(summarizeEngagementCheckpoint(checkpoint)).toEqual({
      coverage: { total: 4, tested: 2, blocked: 1, untested: 1 },
      missions: 2,
      workers: 2,
      obligationsPerMission: 2,
      avoidedPerCellWorkers: 2,
      consolidatedAssociations: 1,
      canonicalRequirements: 3,
      singletonRequirements: 2,
      preflightBlockedAssociations: 0,
      missionProgress: {
        planningStatus: "complete",
        total: 2,
        completed: 1,
        blocked: 1,
        failed: 0,
        running: 0,
        queued: 0,
        items: [
          {
            id: "mission-1",
            workerId: "worker-1",
            purpose: "Test shared authorization",
            status: "completed",
            canonicalRequirements: 1,
            sourceAssociations: 2,
            startedAt: undefined,
            completedAt: undefined,
          },
          {
            id: "mission-2",
            workerId: "worker-2",
            purpose: "Test account recovery",
            status: "blocked",
            canonicalRequirements: 2,
            sourceAssociations: 2,
            startedAt: undefined,
            completedAt: undefined,
          },
        ],
      },
    });

    expect(projectEngagementMissionProgress(checkpoint).items).toHaveLength(2);
  });
});
