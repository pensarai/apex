import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createEngagementPlanningFileTools,
  prepareEngagementPlanningArtifacts,
  sealEngagementPlanArtifact,
} from "./engagementPlanning";
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
  const artifacts = prepareEngagementPlanningArtifacts(directory, store);
  const tools = createEngagementPlanningFileTools(directory, artifacts, store);
  return { artifacts, directory, state, store, tools };
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

function requirement(
  id: string,
  coverage: Array<{ targetId: string; objectiveId: string }>,
) {
  return {
    id,
    description: `Assess ${id}`,
    rationale: "The source associations share the reviewed boundary",
    coverage,
  };
}

function mission(id: string, requirements: ReturnType<typeof requirement>[]) {
  return {
    id,
    purpose: `Test ${id}`,
    rationale: "The targets share an authorization flow",
    requirements,
    supportingTargetIds: [],
    contextTargetIds: [],
    prerequisiteMissionIds: [],
  };
}

function writeReadyPlan(
  path: string,
  contractHash: string,
  missions: ReturnType<typeof mission>[],
) {
  writeFileSync(
    path,
    `${JSON.stringify({
      version: 1,
      status: "ready",
      contractHash,
      missions,
    })}\n`,
    "utf8",
  );
}

describe("engagement mission planning artifacts", () => {
  it("creates a durable manifest and resumable draft", () => {
    const { artifacts, state } = setup(2);
    const manifest = JSON.parse(readFileSync(artifacts.manifestPath, "utf8"));
    const plan = JSON.parse(readFileSync(artifacts.planPath, "utf8"));

    expect(manifest.contractHash).toBe(artifacts.contractHash);
    expect(manifest.targets).toHaveLength(state.targets.length);
    expect(manifest.coverageAssociationCount).toBe(state.coverage.length);
    expect(plan).toEqual({
      version: 2,
      status: "draft",
      contractHash: artifacts.contractHash,
      planningNotes: "",
      requirements: [],
      missions: [],
      consolidationReview: {
        status: "complete",
        summary: "Review pending",
      },
    });
  });

  it("preserves an interrupted draft for the resumed planner to repair", () => {
    const { artifacts, directory, store } = setup(2);
    writeFileSync(artifacts.planPath, "{ interrupted", "utf8");

    prepareEngagementPlanningArtifacts(directory, store);

    expect(readFileSync(artifacts.planPath, "utf8")).toBe("{ interrupted");
  });

  it("limits planning file access to explicitly authorized artifacts", async () => {
    const { artifacts, directory, store } = setup(2);
    const preflightPath = join(
      directory,
      "coordination",
      "engagement-preflight.json",
    );
    writeFileSync(preflightPath, '{"status":"sealed"}\n', "utf8");
    const tools = createEngagementPlanningFileTools(
      directory,
      artifacts,
      store,
      [preflightPath],
    );
    const result = await execute(tools.read_file, {
      path: artifacts.manifestRelativePath,
      toolCallDescription: "Read manifest",
    });
    expect(result).toMatchObject({ success: true });
    expect(store.snapshot().missions?.inspectedTargetIds).toHaveLength(2);
    await expect(
      execute(tools.read_file, {
        path: "coordination/engagement-preflight.json",
        toolCallDescription: "Read deployment preflight",
      }),
    ).resolves.toMatchObject({ success: true });

    await expect(
      execute(tools.read_file, {
        path: "../secret.txt",
        toolCallDescription: "Read another file",
      }),
    ).rejects.toThrow("only read authorized engagement planning artifacts");
    await expect(
      execute(tools.create_file, {
        path: artifacts.manifestRelativePath,
        content: "{}",
        overwrite: true,
        toolCallDescription: "Overwrite manifest",
      }),
    ).rejects.toThrow("only write the engagement plan");
  });

  it("imports, validates, and seals a grouped plan without starting workers", () => {
    const { artifacts, state, store } = setup(8);
    store.recordInspectedTargets(state.targets.map((target) => target.id));
    const missions = [];
    for (let offset = 0; offset < state.coverage.length; offset += 2) {
      const cells = state.coverage
        .slice(offset, offset + 2)
        .map(({ targetId, objectiveId }) => ({ targetId, objectiveId }));
      missions.push(
        mission(
          `resource-flow-${offset / 2 + 1}`,
          cells.map((cell, index) =>
            requirement(`resource-${offset + index + 1}`, [cell]),
          ),
        ),
      );
    }
    writeReadyPlan(artifacts.planPath, artifacts.contractHash, missions);

    const sealed = sealEngagementPlanArtifact(artifacts, store);

    expect(sealed.planningStatus).toBe("complete");
    expect(
      store.snapshot().coverage.every((cell) => cell.status === "assigned"),
    ).toBe(true);
    expect(store.snapshot().workers).toEqual([]);
    expect(JSON.parse(readFileSync(artifacts.planPath, "utf8")).status).toBe(
      "sealed",
    );
  });

  it("rejects incomplete coverage without replacing the prior draft state", () => {
    const { artifacts, state, store } = setup(2);
    store.recordInspectedTargets(state.targets.map((target) => target.id));
    const priorMissions = store.snapshot().missions;
    const cell = state.coverage[0];
    if (!cell) throw new Error("Missing test coverage");
    writeReadyPlan(artifacts.planPath, artifacts.contractHash, [
      mission("partial", [
        requirement("partial-requirement", [
          { targetId: cell.targetId, objectiveId: cell.objectiveId },
        ]),
      ]),
    ]);

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow(
      "omits 1 required coverage obligation",
    );
    expect(store.snapshot().missions).toEqual(priorMissions);
  });

  it("requires complete threat-model context before consolidation", () => {
    const { artifacts, state, store } = setup(2);
    store.recordInspectedTargets(state.targets.map((target) => target.id));
    const coverage = state.coverage.map(({ targetId, objectiveId }) => ({
      targetId,
      objectiveId,
    }));
    writeReadyPlan(artifacts.planPath, artifacts.contractHash, [
      mission("authorization", [
        requirement("shared-owner-boundary", coverage),
      ]),
    ]);

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow(
      "Read complete target context",
    );
    for (const target of state.targets) {
      store.recordContextRead(target.id, {
        status: "read",
        version: `version-${target.id}`,
        complete: true,
        hasProductContext: true,
      });
    }
    expect(sealEngagementPlanArtifact(artifacts, store).planningStatus).toBe(
      "complete",
    );
  });

  it("canonicalizes source associations before assigning requirements to v2 missions", () => {
    const { artifacts, state, store } = setup(2);
    store.recordInspectedTargets(state.targets.map((target) => target.id));
    for (const target of state.targets) {
      store.recordContextRead(target.id, {
        status: "read",
        version: `version-${target.id}`,
        complete: true,
        hasProductContext: true,
      });
    }
    const coverage = state.coverage.map(({ targetId, objectiveId }) => ({
      targetId,
      objectiveId,
    }));
    writeFileSync(
      artifacts.planPath,
      `${JSON.stringify({
        version: 2,
        status: "ready",
        contractHash: artifacts.contractHash,
        requirements: [
          {
            id: "shared-owner-boundary",
            description: "Enforce one owner boundary across resource reads",
            rationale: "One actor differential settles both routes",
            equivalenceBasis: {
              trustBoundary: "Authenticated user to peer-owned resource",
              authenticationState: "Two verified standard users",
              expectedBehavior: "Peer-owned records remain inaccessible",
              evidencePlan: "Replay peer IDs with one authenticated session",
            },
            prerequisiteCapabilityIds: ["verified-standard-user"],
            coverage,
          },
        ],
        missions: [
          {
            id: "authorization-flow",
            purpose: "Test the shared owner boundary",
            rationale: "The routes share actor state and evidence",
            requirementIds: ["shared-owner-boundary"],
            supportingTargetIds: [],
            contextTargetIds: [],
            prerequisiteMissionIds: [],
          },
        ],
        consolidationReview: {
          status: "complete",
          summary: "Reviewed both associations against complete context",
        },
      })}\n`,
      "utf8",
    );

    const sealed = sealEngagementPlanArtifact(artifacts, store);

    expect(sealed.missions).toHaveLength(1);
    expect(sealed.missions[0]?.requirements).toEqual([
      expect.objectContaining({
        id: "shared-owner-boundary",
        coverage,
      }),
    ]);
    expect(sealed.missions[0]?.coverage).toEqual(coverage);
  });

  it("rejects singleton v2 requirements without a non-consolidation reason", () => {
    const { artifacts, state, store } = setup(1);
    const cell = state.coverage[0];
    if (!cell) throw new Error("Missing test coverage");
    store.recordInspectedTargets([cell.targetId]);
    store.recordContextRead(cell.targetId, {
      status: "read",
      version: "target-version",
      complete: true,
      hasProductContext: true,
    });
    writeFileSync(
      artifacts.planPath,
      `${JSON.stringify({
        version: 2,
        status: "ready",
        contractHash: artifacts.contractHash,
        requirements: [
          {
            id: "singleton",
            description: "Assess the unique route",
            rationale: "This route may be unique",
            equivalenceBasis: {
              trustBoundary: "Administrator to global state",
              authenticationState: "Administrator",
              expectedBehavior: "Global state remains authorized",
              evidencePlan: "Compare an admin and standard user response",
            },
            prerequisiteCapabilityIds: [],
            coverage: [cell],
          },
        ],
        missions: [
          {
            id: "singleton-mission",
            purpose: "Test the unique route",
            rationale: "Unique administrative flow",
            singletonJustification: "No related target exists",
            requirementIds: ["singleton"],
            supportingTargetIds: [],
            contextTargetIds: [],
            prerequisiteMissionIds: [],
          },
        ],
        consolidationReview: {
          status: "complete",
          summary: "Reviewed the only association",
        },
      })}\n`,
      "utf8",
    );

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow(
      "nonConsolidationReason",
    );
  });

  it("rejects duplicate and unknown v2 requirement references", () => {
    const { artifacts, state, store } = setup(1);
    const cell = state.coverage[0];
    if (!cell) throw new Error("Missing test coverage");
    writeFileSync(
      artifacts.planPath,
      `${JSON.stringify({
        version: 2,
        status: "ready",
        contractHash: artifacts.contractHash,
        requirements: [
          {
            id: "known",
            description: "Assess one route",
            rationale: "One distinct boundary",
            equivalenceBasis: {
              trustBoundary: "User to own record",
              authenticationState: "Verified user",
              expectedBehavior: "Own record is visible",
              evidencePlan: "Read the owned record",
            },
            prerequisiteCapabilityIds: [],
            nonConsolidationReason: "Only one route exposes this record type",
            coverage: [cell],
          },
        ],
        missions: [
          {
            id: "bad-references",
            purpose: "Test references",
            rationale: "Exercise validation",
            singletonJustification: "One target fixture",
            requirementIds: ["known", "known", "missing"],
            supportingTargetIds: [],
            contextTargetIds: [],
            prerequisiteMissionIds: [],
          },
        ],
        consolidationReview: {
          status: "complete",
          summary: "Reviewed fixture",
        },
      })}\n`,
      "utf8",
    );

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow(
      /exactly one mission|unknown canonical requirements/,
    );
  });

  it("requires every v2 requirement target context to be reviewed", () => {
    const { artifacts, state, store } = setup(1);
    const cell = state.coverage[0];
    if (!cell) throw new Error("Missing test coverage");
    store.recordInspectedTargets([cell.targetId]);
    writeFileSync(
      artifacts.planPath,
      `${JSON.stringify({
        version: 2,
        status: "ready",
        contractHash: artifacts.contractHash,
        requirements: [
          {
            id: "review-context",
            description: "Assess one route",
            rationale: "The boundary must be reviewed first",
            equivalenceBasis: {
              trustBoundary: "User to own record",
              authenticationState: "Verified user",
              expectedBehavior: "Own record is visible",
              evidencePlan: "Read the owned record",
            },
            prerequisiteCapabilityIds: [],
            nonConsolidationReason: "Only one route exposes this record type",
            coverage: [cell],
          },
        ],
        missions: [
          {
            id: "context-mission",
            purpose: "Test the reviewed route",
            rationale: "One target fixture",
            singletonJustification: "One target fixture",
            requirementIds: ["review-context"],
            supportingTargetIds: [],
            contextTargetIds: [],
            prerequisiteMissionIds: [],
          },
        ],
        consolidationReview: {
          status: "complete",
          summary: "Reviewed candidate groups",
        },
      })}\n`,
      "utf8",
    );

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow(
      "Review complete target context",
    );
  });
});
