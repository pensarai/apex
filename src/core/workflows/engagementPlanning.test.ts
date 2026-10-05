import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createEngagementPlanningFileTools,
  ENGAGEMENT_PLANNING_PROMPT,
  EngagementPlanArtifact,
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
      "external artifacts, not prompt material",
    );
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "automatically expand each unreviewed consolidation",
    );
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "Reading every target or document is not required",
    );
    expect(ENGAGEMENT_PLANNING_PROMPT).toContain(
      "live validation remains the final oracle",
    );
  });

  it.each([
    "missing",
    "read",
    "unavailable",
  ] as const)("seals independent requirements with an incomplete %s receipt without claiming full review", (status) => {
    const { artifacts, store, state } = setup(2);
    for (const target of state.targets) {
      if (status === "missing") continue;
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

  it.each([
    "missing",
    "read",
    "unavailable",
  ] as const)("expands v2 consolidation with %s context without forging complete review", (status) => {
    const { artifacts, store, state } = setup(2);
    for (const target of state.targets) {
      if (status === "missing") continue;
      store.recordContextRead(target.id, {
        status,
        complete: false,
        hasProductContext: status === "read",
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
    const contextBefore = store.snapshot().contextReads;
    const sealed = sealEngagementPlanArtifact(artifacts, store);
    expect(sealed.planningStatus).toBe("complete");
    expect(sealed.missions).toHaveLength(1);
    expect(sealed.missions[0]?.id).toBe(group.id);
    expect(sealed.missions[0]?.requirements).toEqual(
      first.coverage.map((cell, index) => ({
        ...first,
        id: `${first.id}_source_${index + 1}`,
        coverage: [cell],
        prerequisiteCapabilityIds: [],
        nonConsolidationReason: expect.stringContaining(
          `Host expanded ${first.id}`,
        ),
      })),
    );
    expect(store.snapshot().contextReads).toEqual(contextBefore);
    expect(store.snapshot().missions?.inspectedTargetIds ?? []).toEqual([]);
    const persisted = EngagementPlanArtifact.parse(
      JSON.parse(readFileSync(artifacts.planPath, "utf8")),
    );
    assert(persisted.version === 2);
    expect(persisted.status).toBe("sealed");
    expect(persisted.requirements).toEqual(sealed.missions[0]?.requirements);
  });

  it("seals 131 targets and 1426 source checks without reading the whole manifest or context", async () => {
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

    const summary = await execute(tools.read_file, {
      path: artifacts.manifestRelativePath,
      toolCallDescription: "Inspect manifest counts and schema",
    });
    expect(summary).toMatchObject({
      counts: { targets: 131, objectives: 1426, coverage: 1426 },
    });
    expect(JSON.stringify(summary).length).toBeLessThan(20_000);
    const page = await execute(tools.read_file, {
      path: artifacts.manifestRelativePath,
      query: { section: "targets", limit: 2 },
      toolCallDescription: "Inspect two relevant targets",
    });
    expect(page).toMatchObject({ total: 131, nextOffset: 2 });
    expect(store.snapshot().missions?.inspectedTargetIds).toHaveLength(2);
    expect(store.snapshot().contextReads ?? {}).toEqual({});
    const plan = independentPlan(artifacts, store);
    const requirementsById = new Map(
      plan.requirements.map((item) => [item.id, item]),
    );
    plan.requirements = plan.missions.map((mission) => {
      const first = requirementsById.get(mission.requirementIds[0] ?? "");
      assert(first);
      const coverage = mission.requirementIds.flatMap(
        (id) => requirementsById.get(id)?.coverage ?? [],
      );
      mission.requirementIds = [first.id];
      return { ...first, coverage };
    });
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
    expect(restored.snapshot().missions?.inspectedTargetIds).toHaveLength(2);
    expect(restored.snapshot().contextReads ?? {}).toEqual({});
    expect(sealed.missions.map((mission) => mission.id)).toEqual(
      plan.missions.map((mission) => mission.id),
    );
    expect(
      EngagementPlanArtifact.parse(
        JSON.parse(readFileSync(artifacts.planPath, "utf8")),
      ).status,
    ).toBe("sealed");
  });

  it("preserves an interrupted draft for the resumed planner to repair", () => {
    const { artifacts, directory, store } = setup(2);
    writeFileSync(artifacts.planPath, "{ interrupted", "utf8");

    prepareEngagementPlanningArtifacts(directory, store);

    expect(readFileSync(artifacts.planPath, "utf8")).toBe("{ interrupted");
  });

  it("queries bounded target, objective-text, and coverage pages without automatic surface reads", async () => {
    const { artifacts, state, store, tools } = setup(3);
    const [first, second] = state.targets;
    const [objective] = state.objectives;
    assert(first && second && objective);
    const query = (input: Record<string, unknown>) =>
      execute(tools.read_file, {
        path: artifacts.manifestRelativePath,
        query: input,
        toolCallDescription: "Query relevant planning records",
      });
    expect(
      await query({ section: "targets", offset: 1, limit: 1 }),
    ).toMatchObject({
      total: 3,
      nextOffset: 2,
      items: [{ id: second.id, target: second.target, objectiveCount: 1 }],
    });
    expect(store.snapshot().missions?.inspectedTargetIds).toEqual([second.id]);
    expect(
      await query({ section: "targets", search: "/resources/0" }),
    ).toMatchObject({
      total: 1,
      nextOffset: null,
      items: [{ id: first.id }],
    });
    expect(
      await query({ section: "objectives", targetId: first.id, textLimit: 4 }),
    ).toMatchObject({
      items: [
        {
          id: objective.id,
          text: "Test",
          totalChars: objective.text.length,
          nextTextOffset: 4,
        },
      ],
    });
    expect(
      await query({
        section: "objectives",
        objectiveId: objective.id,
        textOffset: 4,
      }),
    ).toMatchObject({
      items: [{ text: " authorization", nextTextOffset: null }],
    });
    expect(
      await query({
        section: "coverage",
        targetId: first.id,
        objectiveId: objective.id,
      }),
    ).toMatchObject({
      total: 1,
      nextOffset: null,
      items: [{ targetId: first.id, objectiveId: objective.id }],
    });
    expect(
      await query({ section: "coverage", objectiveId: objective.id, limit: 2 }),
    ).toMatchObject({ total: 3, nextOffset: 2 });
    expect(
      await query({ section: "objectives", search: "no matching objective" }),
    ).toMatchObject({ total: 0, items: [], nextOffset: null });
    await expect(
      query({ section: "targets", targetId: "unknown" }),
    ).rejects.toThrow("Unknown engagement target");
    await expect(query({ section: "targets", limit: 101 })).rejects.toThrow();
    await expect(
      execute(tools.read_file, {
        path: artifacts.planRelativePath,
        query: { section: "targets" },
      }),
    ).rejects.toThrow("Manifest queries require the manifest path");
    await expect(
      execute(tools.read_file, {
        path: artifacts.manifestRelativePath,
        startLine: 1,
        query: { section: "targets" },
      }),
    ).rejects.toThrow("cannot be combined with line bounds");
  });

  it("bounds large objective text independently of record pagination", async () => {
    const { directory } = setup(1);
    const state = buildEngagementState("https://example.test", [
      {
        target: "https://example.test/large",
        objectives: Array.from(
          { length: 12 },
          (_, index) => `${index}:${"Owner policy. ".repeat(10_000)}`,
        ),
      },
    ]);
    const store = EngagementStore.open(join(directory, "large"), state);
    const artifacts = prepareEngagementPlanningArtifacts(
      join(directory, "large"),
      store,
    );
    const tools = createEngagementPlanningFileTools(
      join(directory, "large"),
      artifacts,
      store,
    );
    const page = (await execute(tools.read_file, {
      path: artifacts.manifestPath,
      query: { section: "objectives", limit: 12, textLimit: 16_000 },
    })) as {
      items: Array<{ text: string; nextTextOffset: number }>;
      nextOffset: number;
    };
    expect(page.items.length).toBeGreaterThan(0);
    expect(page.items.length).toBeLessThan(12);
    expect(page.nextOffset).toBe(page.items.length);
    expect(JSON.stringify(page).length).toBeLessThan(81_000);
    expect(
      page.items.every(
        (item) => item.text.length === 16_000 && item.nextTextOffset === 16_000,
      ),
    ).toBe(true);
    const line =
      readFileSync(artifacts.manifestPath, "utf8")
        .split("\n")
        .findIndex((value) => value.length > 100_000) + 1;
    expect(line).toBeGreaterThan(0);
    await expect(
      execute(tools.read_file, {
        path: artifacts.manifestPath,
        startLine: line,
        endLine: line,
      }),
    ).rejects.toThrow("use a bounded manifest query");
    const summary = await execute(tools.read_file, {
      path: artifacts.manifestPath,
    });
    expect(JSON.stringify(summary).length).toBeLessThan(20_000);
  });

  it("expands 100 source checks without changing mission identity, roles, prerequisites, or coverage", () => {
    const { artifacts, store, state } = setup(104);
    const plan = independentPlan(artifacts, store);
    const [first] = plan.requirements;
    const [initialMission] = plan.missions;
    const [target] = state.targets;
    assert(first && initialMission && target);
    const requirements = [
      {
        ...first,
        id: "shared",
        coverage: plan.requirements
          .slice(0, 100)
          .flatMap((item) => item.coverage),
        prerequisiteCapabilityIds: ["two-users"],
      },
      ...plan.requirements.slice(100).map((item, index) => ({
        ...item,
        id: index === 0 ? "shared_source_1" : item.id,
      })),
    ];
    const missions = [
      {
        ...initialMission,
        id: "setup",
        requirementIds: requirements.slice(1).map((item) => item.id),
      },
      {
        ...initialMission,
        id: "flow",
        requirementIds: ["shared"],
        requiredActorRoles: ["owner", "peer"],
        prerequisiteMissionIds: ["setup"],
        supportingTargetIds: [target.id],
        contextTargetIds: [target.id],
      },
    ];
    writeFileSync(
      artifacts.planPath,
      JSON.stringify({ ...plan, requirements, missions }),
    );

    const sealed = sealEngagementPlanArtifact(artifacts, store);
    const flow = sealed.missions.find((mission) => mission.id === "flow");
    assert(flow);
    expect(flow).toMatchObject({
      id: "flow",
      requiredActorRoles: ["owner", "peer"],
      prerequisiteMissionIds: ["setup"],
      supportingTargetIds: [target.id],
      contextTargetIds: [target.id],
    });
    expect(flow.requirements).toHaveLength(100);
    expect(
      flow.requirements?.every(
        (item) =>
          item.prerequisiteCapabilityIds?.[0] === "two-users" &&
          item.coverage.length === 1,
      ),
    ).toBe(true);
    expect(flow.coverage).toEqual(requirements[0]?.coverage);
    const persisted = EngagementPlanArtifact.parse(
      JSON.parse(readFileSync(artifacts.planPath, "utf8")),
    );
    assert(persisted.version === 2);
    const ids = persisted.requirements.map((item) => item.id);
    expect(new Set(ids).size).toBe(104);
    expect(ids).toContain("shared_source_1_1");
    expect(
      persisted.missions.find((mission) => mission.id === "flow")
        ?.requirementIds,
    ).toEqual(flow.requirements?.map((item) => item.id));
  });

  it.each([
    "duplicate",
    "unknown",
    "omitted",
  ] as const)("rejects %s source coverage atomically even when expansion is needed", (kind) => {
    const { artifacts, store } = setup(3);
    const plan = independentPlan(artifacts, store);
    const [first, second, third] = plan.requirements;
    const [group] = plan.missions;
    assert(first && second && third?.coverage[0] && group);
    first.coverage.push(...second.coverage);
    if (kind === "duplicate") first.coverage.push(...second.coverage);
    if (kind === "unknown") third.coverage[0].objectiveId = "unknown-objective";
    plan.requirements = kind === "omitted" ? [first] : [first, third];
    group.requirementIds = plan.requirements.map((item) => item.id);
    const draft = JSON.stringify(plan);
    writeFileSync(artifacts.planPath, draft);
    const before = store.checkpoint();

    expect(() => sealEngagementPlanArtifact(artifacts, store)).toThrow();
    expect(store.checkpoint()).toEqual({
      ...before,
      updatedAt: expect.any(String),
    });
    expect(readFileSync(artifacts.planPath, "utf8")).toBe(draft);
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
    expect(result).toMatchObject({
      success: true,
      counts: { targets: 2, objectives: 1, coverage: 2 },
    });
    expect(result).not.toHaveProperty("content");
    expect(result).not.toHaveProperty("targets");
    expect(store.snapshot().missions?.inspectedTargetIds ?? []).toEqual([]);
    await expect(
      execute(tools.read_file, {
        path: "coordination/engagement-preflight.json",
        toolCallDescription: "Read deployment preflight",
      }),
    ).resolves.toMatchObject({ success: true });

    await expect(
      execute(tools.read_file, {
        path: "../secret.txt",
        query: { section: "summary" },
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

  it("expands unreviewed v1 consolidation into independent checks", () => {
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

    const sealed = sealEngagementPlanArtifact(artifacts, store);
    expect(sealed.planningStatus).toBe("complete");
    expect(
      sealed.missions[0]?.requirements?.map((item) => item.coverage),
    ).toEqual(coverage.map((cell) => [cell]));
    expect(
      sealed.missions[0]?.requirements?.every((item) =>
        item.nonConsolidationReason?.includes("Host expanded"),
      ),
    ).toBe(true);
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

  it("still rejects unreviewed shared coverage if the artifact normalizer is bypassed", () => {
    const { store, state } = setup(2);
    const coverage = state.coverage.map(({ targetId, objectiveId }) => ({
      targetId,
      objectiveId,
    }));
    store.defineMission({
      ...mission("direct", [requirement("shared", coverage)]),
      coverage,
      workerId: "worker-direct",
      status: "planned",
      createdAt: new Date().toISOString(),
    });
    expect(() => store.setMissionPlanningComplete()).toThrow(
      "Read complete target context",
    );
    expect(
      store.snapshot().coverage.every((cell) => cell.status === "pending"),
    ).toBe(true);
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

  it("seals a singleton without requiring target context review", () => {
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

    expect(sealEngagementPlanArtifact(artifacts, store).planningStatus).toBe(
      "complete",
    );
    expect(store.snapshot().contextReads ?? {}).toEqual({});
  });
});
