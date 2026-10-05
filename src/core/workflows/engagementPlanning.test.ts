import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createEngagementPlanningFileTools,
  ENGAGEMENT_PLANNING_PROMPT,
  prepareEngagementPlanningArtifacts,
  sealEngagementPlanArtifact,
} from "./engagementPlanning";
import { buildEngagementState, EngagementStore } from "./engagementState";
import { EngagementContext } from "./engagementSurface";

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

function independentPlan(
  artifacts: ReturnType<typeof prepareEngagementPlanningArtifacts>,
  store: EngagementStore,
) {
  const requirements = store
    .snapshot()
    .coverage.map(({ targetId, objectiveId }, index) => ({
      ...requirement(`requirement-${index}`, [{ targetId, objectiveId }]),
      equivalenceBasis: {
        trustBoundary: "User to a resource's ownership boundary",
        authenticationState: "Owner and peer users",
        expectedBehavior: "Peer-owned records remain inaccessible",
        evidencePlan: "Compare owner and peer access to this target",
      },
      nonConsolidationReason:
        "The full ownership policy is not reviewed, so equivalence of expected behavior with other associations is unverified",
    }));
  const missions = [];
  for (let offset = 0; offset < requirements.length; offset += 25) {
    missions.push({
      id: `mission-${offset}`,
      purpose: "Test related resource access with independent observations",
      rationale: "Shared actor setup, with separate coverage for each check",
      singletonJustification: "Remaining checks concern one resource",
      requirementIds: requirements
        .slice(offset, offset + 25)
        .map((item) => item.id),
    });
  }
  return {
    version: 2,
    status: "ready",
    contractHash: artifacts.contractHash,
    requirements,
    missions,
    consolidationReview: {
      status: "complete",
      summary: "Keep unverified equivalence separate without omitting checks",
    },
  };
}

describe("engagement mission planning artifacts", () => {
  it("creates a durable manifest and resumable draft", () => {
    const { artifacts, state } = setup(2);
    const manifest = JSON.parse(readFileSync(artifacts.manifestPath, "utf8"));
    const plan = JSON.parse(readFileSync(artifacts.planPath, "utf8"));

    expect(manifest.contractHash).toBe(artifacts.contractHash);
    expect(manifest.targets).toHaveLength(state.targets.length);
    expect(manifest.targets).toEqual(state.targets);
    expect(manifest.objectives).toEqual(state.objectives);
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

  it("guides bounded planning without weakening consolidation or live validation", () => {
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "starting with a bounded page",
    );
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "keep each source association as a separate requirement",
    );
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "read the complete context of every affected target",
    );
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "live validation remains the final oracle",
    );
  });

  it.each([
    "read",
    "unavailable",
  ] as const)("seals independent requirements with an incomplete %s receipt without claiming full review", (status) => {
    const { artifacts, store, state } = setup(2);
    store.recordInspectedTargets(state.targets.map((target) => target.id));
    for (const target of state.targets) {
      store.recordContextRead(target.id, {
        status,
        complete: false,
        hasProductContext: status === "read",
      });
    }
    const plan = independentPlan(artifacts, store);
    writeFileSync(artifacts.planPath, JSON.stringify(plan));

    expect(sealEngagementPlanArtifact(artifacts, store).planningStatus).toBe(
      "complete",
    );
    expect(
      Object.values(store.snapshot().contextReads ?? {}).every(
        (receipt) => receipt.complete === false,
      ),
    ).toBe(true);
    expect(store.snapshot().missions?.missions[0]?.requirements).toHaveLength(
      2,
    );
  });

  it("rejects v2 consolidation after partial reads and explains the bounded alternative", () => {
    const { artifacts, store, state } = setup(2);
    store.recordInspectedTargets(state.targets.map((target) => target.id));
    for (const target of state.targets) {
      store.recordContextRead(target.id, {
        status: "read",
        complete: false,
        hasProductContext: true,
      });
    }
    const plan = independentPlan(artifacts, store);
    const [first, second] = plan.requirements;
    const [group] = plan.missions;
    assert(first && second && group);
    first.coverage.push(...second.coverage);
    plan.requirements.splice(1);
    group.requirementIds.splice(1);
    writeFileSync(artifacts.planPath, JSON.stringify(plan));
    const before = store.checkpoint();

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow(
      "split its coverage into separate requirements",
    );
    expect(store.checkpoint()).toEqual({
      ...before,
      updatedAt: expect.any(String),
    });
    expect(JSON.parse(readFileSync(artifacts.planPath, "utf8")).status).toBe(
      "ready",
    );
  });

  it("seals 131 targets and 1426 independent checks after bounded context reads", async () => {
    const directory = mkdtempSync(join(tmpdir(), "apex-planning-scale-"));
    directories.push(directory);
    const state = buildEngagementState(
      "https://example.test",
      Array.from({ length: 131 }, (_, index) => ({
        target: `https://example.test/resources/${index}`,
        objectives: Array.from(
          { length: index < 15 ? 10 : 11 },
          (_, objective) =>
            `Check ${index}/${objective}: ${"Verify resource ownership. ".repeat(100)}`,
        ),
      })),
    );
    const store = EngagementStore.open(directory, state);
    store.saveMissions({ planningStatus: "pending", missions: [] });
    const artifacts = prepareEngagementPlanningArtifacts(directory, store);
    const tools = createEngagementPlanningFileTools(
      directory,
      artifacts,
      store,
    );
    const manifestText = readFileSync(artifacts.manifestPath, "utf8");
    const manifest = JSON.parse(manifestText);
    const objectivesById = new Map(
      state.objectives.map((objective) => [objective.id, objective]),
    );
    const legacyManifest = {
      ...manifest,
      targets: state.targets.map((target) => ({
        ...target,
        objectives: target.objectiveIds.map((id) => {
          const objective = objectivesById.get(id);
          assert(objective);
          return { id, text: objective.text };
        }),
      })),
    };
    const legacySize = JSON.stringify(legacyManifest, null, 2).length;
    expect(legacySize).toBeGreaterThan(6_500_000);
    expect(manifestText.length).toBeLessThan(legacySize * 0.65);
    expect(manifest.objectives).toEqual(state.objectives);
    expect(manifest.coverageAssociationCount).toBe(1426);
    expect(artifacts.contractHash).toBe(
      createHash("sha256")
        .update(
          JSON.stringify({
            rootTarget: state.rootTarget,
            operatorContext: state.operatorContext,
            services: state.services,
            objectives: state.objectives,
            targets: legacyManifest.targets,
          }),
        )
        .digest("hex"),
    );

    let startLine = 1;
    let totalLines = Infinity;
    while (startLine <= totalLines) {
      const page = (await execute(tools.read_file, {
        path: artifacts.manifestRelativePath,
        startLine,
        toolCallDescription: "Read a bounded manifest page",
      })) as { linesReturned: number; totalLines: number; content: string };
      expect(page.linesReturned).toBeGreaterThan(0);
      expect(page.content.length).toBeLessThan(100_100);
      startLine += page.linesReturned;
      totalLines = page.totalLines;
    }
    const targetsById = new Map(
      state.targets.map((target) => [target.id, target]),
    );
    const context = new EngagementContext({
      targetIds: targetsById.keys(),
      provider: {
        search: async () => ({ targets: [], total: 131 }),
        getTarget: async (id) => {
          const target = targetsById.get(id);
          assert(target);
          return {
            id,
            applicationId: "resources",
            applicationName: "Resource service",
            target: target.target,
            businessLogic: "Only owners may read their resources. ".repeat(
              2000,
            ),
            threatModel: "Peers must not cross the ownership boundary",
            objectives: target.objectiveIds.map((objectiveId) => {
              const objective = objectivesById.get(objectiveId);
              assert(objective);
              return objective.text;
            }),
          };
        },
      },
      onRead: ({ targetId, ...receipt }) =>
        store.recordContextRead(targetId, receipt),
    });
    for (const target of state.targets) {
      const page = await context.read(target.id);
      expect(page.success).toBe(true);
      if (!page.success) throw new Error("Expected available context");
      expect(page.contextJson.length).toBe(12_000);
      expect(page.nextOffset).not.toBeNull();
    }
    expect(context.receipts().every((receipt) => !receipt.complete)).toBe(true);
    const plan = independentPlan(artifacts, store);
    writeFileSync(artifacts.planPath, JSON.stringify(plan));
    const restored = EngagementStore.open(directory, state);

    const sealed = sealEngagementPlanArtifact(artifacts, restored);

    expect(sealed.planningStatus).toBe("complete");
    expect(
      sealed.missions.every((mission) => mission.status === "queued"),
    ).toBe(true);
    expect(sealed.missions.flatMap((mission) => mission.coverage)).toEqual(
      state.coverage.map(({ targetId, objectiveId }) => ({
        targetId,
        objectiveId,
      })),
    );
    expect(
      sealed.missions.flatMap((mission) => mission.requirements),
    ).toHaveLength(1426);
    expect(
      restored.snapshot().coverage.every((cell) => cell.status === "assigned"),
    ).toBe(true);
    expect(restored.snapshot().workers).toEqual([]);
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
      "Review target context",
    );
  });
});
