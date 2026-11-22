import { describe, expect, it } from "vitest";
import type { EngagementPlan } from "./engagementPlan";
import {
  createEngagementState,
  engagementStatePage,
  isEngagementTerminal,
} from "./engagementState";

function fixture(count: number) {
  const plan: EngagementPlan = {
    version: 1,
    status: "sealed",
    contractHash: "test",
    decisions: [],
    coverageObligations: [],
    missions: Array.from({ length: count }, (_, i) => ({
      id: `m${i}`,
      purpose: "Test boundary",
      dependsOn: [],
      obligationIds: [],
      assignments: [{ targetId: `t${i}`, objectiveId: "auth" }],
    })),
  };
  const state = createEngagementState(plan);
  for (const mission of state.missions) {
    mission.status = "completed";
    mission.result = {
      summary: "Evidence ".repeat(1000),
      reportedFindings: [],
      coverage: [],
    };
    state.coverage.push({
      ...mission.assignments[0],
      status: "tested",
      summary: "Checked",
      evidence: "Response ".repeat(1000),
    });
    state.obligations.push({
      id: mission.id,
      kind: "boundary",
      targetIds: [mission.assignments[0].targetId],
      description: "Boundary ".repeat(1000),
      verification: "Request ".repeat(1000),
    });
    state.obligationResults.push({
      obligationId: mission.id,
      status: "tested",
      evidence: "Proof ".repeat(1000),
      landedIds: [],
    });
    state.chains.push({
      id: mission.id,
      targetIds: [mission.assignments[0].targetId],
      hypothesis: "Chain ".repeat(1000),
      prerequisites: ["Token"],
      steps: ["Step ".repeat(1000)],
      impact: "Access",
      status: "disproved",
      evidence: "Proof ".repeat(1000),
    });
  }
  return { plan, state };
}

describe("engagement state views", () => {
  it("bounds automatic views independently of accumulated mission evidence", () => {
    const { plan, state } = fixture(500);
    const page = engagementStatePage(plan, state, 0, 2);
    expect(page.missions.map((item) => item.id)).toEqual(["m0", "m1"]);
    expect(page).toMatchObject({
      totalMissions: 500,
      completedPairs: 500,
      totalPairs: 500,
      nextMissionOffset: 2,
      nextObligationOffset: 2,
      nextChainOffset: 2,
    });
    expect(page.obligations).toHaveLength(2);
    expect(page.chains).toHaveLength(2);
    expect(page.missions[0]).not.toHaveProperty("result");
    expect(page.obligations[0]).not.toHaveProperty("evidence");
    expect(JSON.stringify(page).length).toBeLessThan(3000);
    expect(engagementStatePage(plan, state, 499, 2)).toMatchObject({
      nextMissionOffset: null,
      nextObligationOffset: null,
      nextChainOffset: null,
    });
    expect(state.missions[0]?.result?.summary.length).toBeGreaterThan(1000);
  });

  it("keeps unresolved obligations and chains visible in counts and paged summaries", () => {
    const { plan, state } = fixture(3);
    state.coverage.pop();
    state.obligationResults.pop();
    state.chains[2].status = "open";
    expect(engagementStatePage(plan, state, 0, 1)).toMatchObject({
      completedPairs: 2,
      openPairs: [{ targetId: "t2", objectiveId: "auth" }],
      resolvedObligations: 2,
      openChains: 1,
    });
    expect(engagementStatePage(plan, state, 2, 1)).toMatchObject({
      obligations: [{ id: "m2", status: "unresolved" }],
      chains: [{ id: "m2", status: "open" }],
    });
    expect(isEngagementTerminal(plan, state)).toBe(false);
  });

  it("keeps state-view mutations out of the authoritative assignments", () => {
    const { plan, state } = fixture(1);
    state.coverage = [];
    const page = engagementStatePage(plan, state);
    page.openPairs[0].targetId = "changed";
    page.missions[0].status = "pending";
    expect(state.missions[0].assignments[0].targetId).toBe("t0");
    expect(state.missions[0].status).toBe("completed");
  });

  it("checks coverage with linear record access instead of a scan per objective", () => {
    const { plan, state } = fixture(200);
    let reads = 0;
    for (const cell of state.coverage) {
      const id = cell.targetId;
      Object.defineProperty(cell, "targetId", {
        get: () => {
          reads++;
          return id;
        },
      });
    }
    expect(isEngagementTerminal(plan, state)).toBe(true);
    engagementStatePage(plan, state);
    expect(reads).toBeLessThan(state.coverage.length * 4);
    state.missions[0].status = "submitted";
    expect(isEngagementTerminal(plan, state)).toBe(false);
  });
});
