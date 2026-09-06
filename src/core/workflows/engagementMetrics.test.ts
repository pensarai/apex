import { describe, expect, it } from "vitest";
import { summarizeEngagementCheckpoint } from "./engagementMetrics";
import type { EngagementCheckpoint } from "./engagementState";

describe("summarizeEngagementCheckpoint", () => {
  it("separates tested, blocked, and untested while measuring grouping", () => {
    const checkpoint = {
      coverage: [
        { status: "exhausted" },
        { status: "impact-proven" },
        { status: "blocked" },
        { status: "running" },
      ],
      workers: [{}, {}],
      missions: { missions: [{}, {}] },
    } as EngagementCheckpoint;

    expect(summarizeEngagementCheckpoint(checkpoint)).toEqual({
      coverage: { total: 4, tested: 2, blocked: 1, untested: 1 },
      missions: 2,
      workers: 2,
      obligationsPerMission: 2,
      avoidedPerCellWorkers: 2,
    });
  });
});
