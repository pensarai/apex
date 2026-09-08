import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEngagementPlanningTools } from "./engagementPlanning";
import { buildEngagementState, EngagementStore } from "./engagementState";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function setup(count: number) {
  const directory = mkdtempSync(join(tmpdir(), "apex-planning-"));
  directories.push(directory);
  const state = buildEngagementState(
    "https://example.test",
    Array.from({ length: count }, (_, index) => ({
      target: `https://example.test/api/resources/${index}`,
      objectives: ["Test authorization"],
    })),
  );
  const store = EngagementStore.open(directory, state);
  store.saveMissions({ planningStatus: "pending", missions: [] });
  const tools = createEngagementPlanningTools(store);
  return { state, store, tools };
}

async function execute(value: unknown, input: Record<string, unknown>) {
  return (
    value as {
      execute: (
        input: Record<string, unknown>,
        context: { toolCallId: string; messages: never[] },
      ) => Promise<unknown>;
    }
  ).execute(input, {
    toolCallId: "call-1",
    messages: [],
  });
}

describe("engagement mission planning", () => {
  it("requires the planner to read the complete manifest", async () => {
    const { state, tools } = setup(2);
    await execute(tools.read_engagement_manifest, {
      offset: 0,
      limit: 1,
      toolCallDescription: "read one target",
    });
    await execute(tools.define_engagement_mission, {
      purpose: "Test the shared resource flow",
      rationale: "The targets share authorization state",
      coverage: state.coverage,
      supportingTargetIds: [],
      contextTargetIds: [],
      prerequisiteMissionIds: [],
      toolCallDescription: "define mission",
    });
    await expect(
      execute(tools.complete_engagement_mission_plan, {
        toolCallDescription: "seal plan",
      }),
    ).rejects.toThrow("complete target manifest");
  });

  it("rejects singleton-heavy large plans", async () => {
    const { state, tools } = setup(8);
    await execute(tools.read_engagement_manifest, {
      offset: 0,
      limit: 25,
      toolCallDescription: "read all targets",
    });
    for (const cell of state.coverage) {
      await execute(tools.define_engagement_mission, {
        purpose: `Test ${cell.targetId}`,
        rationale: "Dedicated target test",
        singletonJustification: "Isolated target",
        coverage: [cell],
        supportingTargetIds: [],
        contextTargetIds: [],
        prerequisiteMissionIds: [],
        toolCallDescription: "define singleton",
      });
    }
    await expect(
      execute(tools.complete_engagement_mission_plan, {
        toolCallDescription: "seal plan",
      }),
    ).rejects.toThrow("Regroup the plan");
  });

  it("seals grouped coverage as assigned without starting workers", async () => {
    const { state, store, tools } = setup(8);
    await execute(tools.read_engagement_manifest, {
      offset: 0,
      limit: 25,
      toolCallDescription: "read all targets",
    });
    for (let offset = 0; offset < state.coverage.length; offset += 2) {
      await execute(tools.define_engagement_mission, {
        purpose: `Test related resource flow ${offset / 2 + 1}`,
        rationale: "The resources share authorization state",
        coverage: state.coverage.slice(offset, offset + 2),
        supportingTargetIds: [],
        contextTargetIds: [],
        prerequisiteMissionIds: [],
        toolCallDescription: "define grouped mission",
      });
    }
    await execute(tools.complete_engagement_mission_plan, {
      toolCallDescription: "seal plan",
    });
    expect(
      store.snapshot().coverage.every((cell) => cell.status === "assigned"),
    ).toBe(true);
    expect(store.snapshot().workers).toEqual([]);
  });
});
