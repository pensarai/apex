import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolSet } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EngagementJournal } from "./engagementJournal";
import type { EngagementState } from "./engagementState";
import { createCoordinationTools } from "./engagementTools";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
const targets = ["a", "b"].map((id) => ({
  id,
  target: `https://${id}.example`,
  objectives: [{ id: "auth", text: "Test auth" }],
}));
const definition = (id: string, targetId = "a") => ({
  id,
  purpose: "Test authorization",
  assignments: [{ targetId, objectiveId: "auth" }],
  objectives: [],
  dependsOn: [],
  obligationIds: [],
  chainIds: [],
});
function setup() {
  const root = mkdtempSync(join(tmpdir(), "engagement-tools-"));
  roots.push(root);
  const state: EngagementState = {
    version: 2,
    planHash: "test",
    revision: 0,
    missions: [],
    coverage: [],
    reportedFindings: [],
    landed: [],
    obligations: [
      {
        id: "tenant",
        kind: "boundary",
        description: "Tenant isolation",
        targetIds: ["a", "b"],
        verification: "Cross-tenant requests must be denied",
      },
    ],
    obligationResults: [],
    chains: [],
    additionalObjectives: [],
  };
  const options = {
    state,
    targets,
    allowed: new Set(["a", "b"]),
    save: () => {
      state.revision++;
    },
    schedule: vi.fn(),
    cancel: vi.fn(),
    journal: new EngagementJournal(root),
  };
  return { state, options, tools: createCoordinationTools(options) };
}
async function execute(tools: ToolSet, name: string, input: unknown) {
  const method = tools[name]?.execute;
  if (!method) throw new Error(`Missing test tool ${name}`);
  return method(input as never, {} as never);
}
function submit(state: EngagementState, id: string) {
  const mission = state.missions.find((item) => item.id === id);
  if (!mission) throw new Error("Missing fixture mission");
  mission.status = "submitted";
  mission.attempt++;
  mission.result = {
    summary: "Evidence collected",
    coverage: mission.assignments.map((pair) => ({
      ...pair,
      status: "tested",
      summary: "Checked",
      evidence: "Authenticated HTTP requests and access-denied responses",
    })),
    reportedFindings: [],
  };
}

describe("adaptive engagement coordination", () => {
  it("adds scoped objectives and worker subtasks to the shared queue, rejecting scope expansion", async () => {
    const { state, tools, options } = setup();
    await execute(tools, "create_engagement_mission", definition("parent"));
    state.missions[0].status = "running";
    const worker = createCoordinationTools({ ...options, parentId: "parent" });
    await execute(worker, "add_engagement_subtask", {
      ...definition("child"),
      assignments: [{ targetId: "a", objectiveId: "token" }],
      objectives: [
        {
          targetId: "a",
          objectiveId: "token",
          text: "Validate token audience",
        },
      ],
    });
    expect(state.missions[1]).toMatchObject({
      parentId: "parent",
      status: "pending",
    });
    expect(state.additionalObjectives).toHaveLength(1);
    await expect(
      execute(worker, "add_engagement_subtask", definition("escape", "b")),
    ).rejects.toThrow("out-of-scope");
    await expect(
      execute(
        tools,
        "create_engagement_mission",
        definition("external", "outside"),
      ),
    ).rejects.toThrow("out-of-scope");
    await expect(
      execute(worker, "add_engagement_subtask", {
        ...definition("deadlock"),
        dependsOn: ["parent"],
      }),
    ).rejects.toThrow("deadlock");
    expect(worker.accept_engagement_result).toBeUndefined();
    expect(options.schedule).toHaveBeenCalledTimes(2);
  });

  it("requires lead acceptance of the current attempt and retains immutable landed history on reassignment", async () => {
    const { state, tools } = setup();
    await execute(tools, "create_engagement_mission", definition("mission"));
    submit(state, "mission");
    await expect(
      execute(tools, "accept_engagement_result", {
        missionId: "mission",
        attempt: 2,
        review: "Stale",
      }),
    ).rejects.toThrow("matching submitted");
    expect(state.coverage).toEqual([]);
    const landed = await execute(tools, "accept_engagement_result", {
      missionId: "mission",
      attempt: 1,
      review: "Reviewed original requests",
    });
    expect(state.coverage).toHaveLength(1);
    expect(state.landed).toHaveLength(1);
    expect(
      await execute(tools, "accept_engagement_result", {
        missionId: "mission",
        attempt: 1,
        review: "Retry",
      }),
    ).toEqual(landed);
    await execute(tools, "revise_engagement_mission", {
      ...definition("mission", "b"),
      purpose: "Investigate newly discovered service boundary",
    });
    submit(state, "mission");
    await execute(tools, "accept_engagement_result", {
      missionId: "mission",
      attempt: 2,
      review: "Reviewed expanded scope",
    });
    expect(state.landed).toHaveLength(2);
    expect(state.landed[0]).toEqual(landed);
    expect(state.landed[1].result.coverage[0].targetId).toBe("b");
  });

  it("requires landed validation across all affected services to close a boundary or chain", async () => {
    const { state, tools } = setup();
    await execute(tools, "propose_engagement_chain", {
      id: "pivot",
      targetIds: ["a", "b"],
      hypothesis: "A leaked token reaches another service",
      prerequisites: ["Token observed in response"],
      steps: ["Obtain token", "Test audience at B"],
      impact: "Cross-service unauthorized access",
    });
    await execute(tools, "create_engagement_mission", {
      ...definition("first"),
      obligationIds: ["tenant"],
      chainIds: ["pivot"],
    });
    submit(state, "first");
    await execute(tools, "accept_engagement_result", {
      missionId: "first",
      attempt: 1,
      review: "Reviewed token evidence",
    });
    const firstIds = state.landed.map((item) => item.id);
    await expect(
      execute(tools, "resolve_engagement_chain", {
        chainId: "pivot",
        status: "validated",
        evidence: "Token leaked",
        landedIds: firstIds,
      }),
    ).rejects.toThrow("every affected target");
    await expect(
      execute(tools, "resolve_engagement_obligation", {
        obligationId: "tenant",
        status: "tested",
        evidence: "Checked A",
        landedIds: firstIds,
      }),
    ).rejects.toThrow("every affected target");
    await execute(tools, "create_engagement_mission", {
      ...definition("second", "b"),
      obligationIds: ["tenant"],
      chainIds: ["pivot"],
    });
    submit(state, "second");
    await execute(tools, "accept_engagement_result", {
      missionId: "second",
      attempt: 1,
      review: "Reviewed audience rejection",
    });
    const landedIds = state.landed.map((item) => item.id);
    await execute(tools, "resolve_engagement_chain", {
      chainId: "pivot",
      status: "disproved",
      evidence: "B rejected A's token",
      landedIds,
    });
    await execute(tools, "resolve_engagement_obligation", {
      obligationId: "tenant",
      status: "tested",
      evidence: "Both services rejected cross-tenant access",
      landedIds,
    });
    expect(state.chains[0].status).toBe("disproved");
    await execute(tools, "create_engagement_mission", {
      ...definition("new-evidence"),
      obligationIds: ["tenant"],
      chainIds: ["pivot"],
    });
    expect(state.chains[0].status).toBe("open");
    expect(state.obligationResults).toEqual([]);
    expect(state.landed).toHaveLength(2);
  });

  it("keeps a parent unlanded until its subtasks are reviewed", async () => {
    const { state, tools } = setup();
    await execute(tools, "create_engagement_mission", definition("parent"));
    await execute(tools, "create_engagement_mission", {
      ...definition("child"),
      parentId: "parent",
    });
    submit(state, "parent");
    submit(state, "child");
    await expect(
      execute(tools, "accept_engagement_result", {
        missionId: "parent",
        attempt: 1,
        review: "Ready",
      }),
    ).rejects.toThrow("subtasks first");
    await execute(tools, "accept_engagement_result", {
      missionId: "child",
      attempt: 1,
      review: "Reviewed child evidence",
    });
    await execute(tools, "accept_engagement_result", {
      missionId: "parent",
      attempt: 1,
      review: "Reviewed combined evidence",
    });
    expect(state.landed.map((item) => item.missionId)).toEqual([
      "child",
      "parent",
    ]);
  });
});
