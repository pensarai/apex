import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { newSessionId } from "../id/id";
import type {
  EngagementMission,
  EngagementMissionRequirement,
  EngagementMissionState,
} from "./engagementMissions";
import type { EngagementStore } from "./engagementState";

export const ENGAGEMENT_MANIFEST_RELATIVE_PATH =
  "coordination/engagement-planning-manifest.json";
export const ENGAGEMENT_PLAN_RELATIVE_PATH =
  "coordination/engagement-plan.json";

const CoverageAssociation = z.object({
  targetId: z.string().min(1),
  objectiveId: z.string().min(1),
});

const PlanningRequirementV1 = z.object({
  id: z.string().min(1).max(120),
  description: z.string().min(1).max(4_000),
  rationale: z.string().min(1).max(4_000),
  coverage: z.array(CoverageAssociation).min(1).max(100),
});

const PlanningMissionV1 = z
  .object({
    id: z.string().min(1).max(120),
    purpose: z.string().min(1).max(4_000),
    rationale: z.string().min(1).max(4_000),
    singletonJustification: z.string().min(1).max(4_000).optional(),
    requirements: z.array(PlanningRequirementV1).min(1).max(25),
    supportingTargetIds: z.array(z.string()).max(100).default([]),
    contextTargetIds: z.array(z.string()).max(100).default([]),
    prerequisiteMissionIds: z.array(z.string()).max(100).default([]),
  })
  .superRefine((mission, context) => {
    const associationCount = mission.requirements.reduce(
      (total, requirement) => total + requirement.coverage.length,
      0,
    );
    if (associationCount > 100) {
      context.addIssue({
        code: "custom",
        message: "A mission may contain at most 100 source associations",
        path: ["requirements"],
      });
    }
  });

const PlanMetrics = z
  .object({
    primaryTargetsPerMission: z.number(),
    singletonTargets: z.number().int().min(0),
  })
  .optional();

const EngagementPlanArtifactV1 = z.object({
  version: z.literal(1),
  status: z.enum(["draft", "ready", "sealed"]),
  contractHash: z.string().min(1),
  planningNotes: z.string().max(100_000).optional(),
  missions: z.array(PlanningMissionV1).min(1),
  metrics: PlanMetrics,
});

const EquivalenceBasis = z.object({
  trustBoundary: z.string().min(1).max(4_000),
  authenticationState: z.string().min(1).max(4_000),
  expectedBehavior: z.string().min(1).max(4_000),
  evidencePlan: z.string().min(1).max(4_000),
});

export const EngagementPlanningRequirementV2 = z
  .object({
    id: z.string().min(1).max(120),
    description: z.string().min(1).max(4_000),
    rationale: z.string().min(1).max(4_000),
    equivalenceBasis: EquivalenceBasis,
    prerequisiteCapabilityIds: z
      .array(z.string().min(1).max(120))
      .max(50)
      .default([]),
    nonConsolidationReason: z.string().min(1).max(4_000).optional(),
    coverage: z.array(CoverageAssociation).min(1).max(100),
  })
  .superRefine((requirement, context) => {
    if (
      requirement.coverage.length === 1 &&
      !requirement.nonConsolidationReason?.trim()
    ) {
      context.addIssue({
        code: "custom",
        message:
          "A singleton canonical requirement needs a nonConsolidationReason",
        path: ["nonConsolidationReason"],
      });
    }
  });

export type EngagementPlanningRequirementV2 = z.infer<
  typeof EngagementPlanningRequirementV2
>;

const PlanningMissionV2 = z.object({
  id: z.string().min(1).max(120),
  purpose: z.string().min(1).max(4_000),
  rationale: z.string().min(1).max(4_000),
  singletonJustification: z.string().min(1).max(4_000).optional(),
  requirementIds: z.array(z.string().min(1).max(120)).min(1).max(25),
  supportingTargetIds: z.array(z.string()).max(100).default([]),
  contextTargetIds: z.array(z.string()).max(100).default([]),
  prerequisiteMissionIds: z.array(z.string()).max(100).default([]),
  requiredActorRoles: z.array(z.string().min(1)).max(20).default([]),
});

const EngagementPlanArtifactV2 = z.object({
  version: z.literal(2),
  status: z.enum(["draft", "ready", "sealed"]),
  contractHash: z.string().min(1),
  planningNotes: z.string().max(100_000).optional(),
  requirements: z.array(EngagementPlanningRequirementV2).min(1),
  missions: z.array(PlanningMissionV2).min(1),
  consolidationReview: z.object({
    status: z.literal("complete"),
    summary: z.string().min(1).max(10_000),
  }),
  metrics: PlanMetrics,
});

export const EngagementPlanArtifact = z
  .union([EngagementPlanArtifactV1, EngagementPlanArtifactV2])
  .superRefine((artifact, context) => {
    const missionIds = artifact.missions.map((mission) => mission.id);
    if (new Set(missionIds).size !== missionIds.length) {
      context.addIssue({
        code: "custom",
        message: "Mission IDs must be unique",
        path: ["missions"],
      });
    }
    if (artifact.version === 1) return;

    const requirementIds = artifact.requirements.map(
      (requirement) => requirement.id,
    );
    if (new Set(requirementIds).size !== requirementIds.length) {
      context.addIssue({
        code: "custom",
        message: "Canonical requirement IDs must be unique",
        path: ["requirements"],
      });
    }
    const knownRequirementIds = new Set(requirementIds);
    const references = artifact.missions.flatMap(
      (mission) => mission.requirementIds,
    );
    if (new Set(references).size !== references.length) {
      context.addIssue({
        code: "custom",
        message:
          "Every canonical requirement must be assigned to exactly one mission",
        path: ["missions"],
      });
    }
    const unknown = references.filter((id) => !knownRequirementIds.has(id));
    if (unknown.length > 0) {
      context.addIssue({
        code: "custom",
        message: `Missions reference unknown canonical requirements: ${[...new Set(unknown)].join(", ")}`,
        path: ["missions"],
      });
    }
    const unassigned = requirementIds.filter(
      (id) => !new Set(references).has(id),
    );
    if (unassigned.length > 0) {
      context.addIssue({
        code: "custom",
        message: `Canonical requirements are not assigned to missions: ${unassigned.join(", ")}`,
        path: ["requirements"],
      });
    }
    const requirementsById = new Map(
      artifact.requirements.map((requirement) => [requirement.id, requirement]),
    );
    for (const [missionIndex, mission] of artifact.missions.entries()) {
      const associationCount = mission.requirementIds.reduce(
        (total, id) => total + (requirementsById.get(id)?.coverage.length ?? 0),
        0,
      );
      if (associationCount > 100) {
        context.addIssue({
          code: "custom",
          message: "A mission may contain at most 100 source associations",
          path: ["missions", missionIndex, "requirementIds"],
        });
      }
    }
  });

export type EngagementPlanningArtifacts = {
  contractHash: string;
  manifestPath: string;
  manifestRelativePath: typeof ENGAGEMENT_MANIFEST_RELATIVE_PATH;
  planPath: string;
  planRelativePath: typeof ENGAGEMENT_PLAN_RELATIVE_PATH;
};

export const ENGAGEMENT_PLANNING_PROMPT = `Plan coherent testing missions for this authorized engagement before testing begins.
Use code mode to read the complete immutable planning manifest and maintain the mission plan as the external JSON artifact named in the user prompt. Keep working memory, clustering notes, and the authoritative draft in that file rather than repeating the full plan in conversation. The manifest's contractHash must remain unchanged. Set the plan status to ready only after checking the whole artifact.

Read the complete target context available through the read-only engagement context capability before deciding equivalence. First canonicalize the source associations into top-level requirements, then assign those requirement IDs to missions. Group related endpoints by authentication, shared resources, trust boundaries, and causal flow. Application code does not choose groups.

Every canonical requirement must state its trust boundary, authentication state, expected behavior, and evidence plan. It may consolidate source endpoint/objective associations only when those dimensions are materially equivalent. Preserve all source associations in requirement coverage and explain why consolidation is sound. For a requirement that remains a singleton, give a concrete nonConsolidationReason naming the dimension that prevents a safe merge. Do not use generic statements such as "keep exact" or "test independently." Reference deployment prerequisite capability IDs when the preflight artifact supplies them.

Every mission must reference canonical requirement IDs and include rationale, context target references, supporting targets, prerequisite mission IDs, and the official actor roles needed to execute it. Use an empty requiredActorRoles array only for genuinely anonymous work. Keep meaningful distinctions separate. Supporting/context targets do not earn coverage credit.

Every source association must be assigned to exactly one canonical requirement. Every singleton mission needs a justification. For eight or more targets, at most 25% of targets may have singleton missions and the plan must average at least two primary targets per mission. Keep missions bounded to 100 source associations and 25 canonical requirements. Never force unrelated endpoints together just to pass a gate. Add prerequisites only for genuine execution dependencies; shared setup alone is not a reason to serialize otherwise independent missions.

Only the scoped read_file, create_file, and read-only engagement context capabilities are available during planning. Do not test the target. When the artifact is ready, call response with planComplete=true and a concise summary. The host will validate and seal the artifact deterministically; do not reproduce the plan in the response.`;

function atomicWrite(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporaryPath, content, "utf8");
  renameSync(temporaryPath, path);
}

function writeJson(path: string, value: unknown): void {
  atomicWrite(path, `${JSON.stringify(value, null, 2)}\n`);
}

function artifactPlanV2(missions: EngagementMission[]) {
  const requirements = missions.flatMap((mission) =>
    (
      mission.requirements ??
      mission.coverage.map((coverage, index) => ({
        id: `${mission.id}_requirement_${index + 1}`,
        description: `Assess ${coverage.targetId} against ${coverage.objectiveId}`,
        rationale: "Preserve the existing source coverage association",
        coverage: [coverage],
      }))
    ).map((requirement) => ({
      ...requirement,
      id: `${mission.id}_${requirement.id}`,
      equivalenceBasis: {
        trustBoundary: "Review required",
        authenticationState: "Review required",
        expectedBehavior: "Review required",
        evidencePlan: "Review required",
      },
      prerequisiteCapabilityIds: [],
      ...(requirement.coverage.length === 1
        ? { nonConsolidationReason: "Review required before sealing" }
        : {}),
    })),
  );
  let requirementOffset = 0;
  const artifactMissions = missions.map((mission) => {
    const requirementCount =
      mission.requirements?.length ?? mission.coverage.length;
    const requirementIds = requirements
      .slice(requirementOffset, requirementOffset + requirementCount)
      .map((requirement) => requirement.id);
    requirementOffset += requirementCount;
    return {
      id: mission.id,
      purpose: mission.purpose,
      rationale: mission.rationale,
      ...(mission.singletonJustification
        ? { singletonJustification: mission.singletonJustification }
        : {}),
      requirementIds,
      supportingTargetIds: mission.supportingTargetIds,
      contextTargetIds: mission.contextTargetIds,
      prerequisiteMissionIds: mission.prerequisiteMissionIds,
    };
  });
  return { requirements, missions: artifactMissions };
}

export function prepareEngagementPlanningArtifacts(
  sessionRootPath: string,
  store: EngagementStore,
): EngagementPlanningArtifacts {
  const state = store.snapshot();
  const contract = {
    rootTarget: state.rootTarget,
    operatorContext: state.operatorContext,
    services: state.services,
    objectives: state.objectives,
    targets: state.targets.map((target) => ({
      ...target,
      objectives: target.objectiveIds.map((objectiveId) => {
        const objective = state.objectives.find(
          (candidate) => candidate.id === objectiveId,
        );
        if (!objective) throw new Error(`Unknown objective: ${objectiveId}`);
        return { id: objective.id, text: objective.text };
      }),
    })),
  };
  const contractHash = createHash("sha256")
    .update(JSON.stringify(contract))
    .digest("hex");
  const manifestPath = join(sessionRootPath, ENGAGEMENT_MANIFEST_RELATIVE_PATH);
  const planPath = join(sessionRootPath, ENGAGEMENT_PLAN_RELATIVE_PATH);
  writeJson(manifestPath, {
    version: 2,
    contractHash,
    coverageAssociationCount: state.coverage.length,
    constraints: {
      maximumSourceAssociationsPerMission: 100,
      maximumRequirementsPerMission: 25,
      maximumSingletonTargetRatioWhenEightOrMoreTargets: 0.25,
      minimumAveragePrimaryTargetsPerMissionWhenEightOrMoreTargets: 2,
    },
    planSchema: {
      version: 2,
      status: "draft | ready",
      contractHash: "Copy this manifest's contractHash unchanged",
      planningNotes: "Optional string for compact working memory",
      requirements: [
        {
          id: "stable-requirement-id",
          description: "Canonical security behavior to assess",
          rationale: "Why its source associations are equivalent",
          equivalenceBasis: {
            trustBoundary: "Shared data and privilege boundary",
            authenticationState: "Actors and credentials used",
            expectedBehavior: "One invariant shared by every association",
            evidencePlan: "One observation that settles every association",
          },
          prerequisiteCapabilityIds: [],
          nonConsolidationReason:
            "Required only when coverage contains one association",
          coverage: [{ targetId: "target ID", objectiveId: "objective ID" }],
        },
      ],
      missions: [
        {
          id: "stable-mission-id",
          purpose: "What this worker tests as one coherent flow",
          rationale: "Why these targets and requirements belong together",
          singletonJustification: "Required only for one-target missions",
          requirementIds: ["stable-requirement-id"],
          supportingTargetIds: [],
          contextTargetIds: [],
          prerequisiteMissionIds: [],
        },
      ],
      consolidationReview: {
        status: "complete",
        summary: "How candidate equivalence groups were reviewed",
      },
    },
    ...contract,
  });

  if (!existsSync(planPath)) {
    const restored = artifactPlanV2(state.missions?.missions ?? []);
    writeJson(planPath, {
      version: 2,
      status: "draft",
      contractHash,
      planningNotes: "",
      requirements: restored.requirements,
      missions: restored.missions,
      consolidationReview: {
        status: "complete",
        summary: "Review pending",
      },
    });
  }

  return {
    contractHash,
    manifestPath,
    manifestRelativePath: ENGAGEMENT_MANIFEST_RELATIVE_PATH,
    planPath,
    planRelativePath: ENGAGEMENT_PLAN_RELATIVE_PATH,
  };
}

function resolvedArtifactPath(sessionRootPath: string, path: string): string {
  return isAbsolute(path) ? resolve(path) : resolve(sessionRootPath, path);
}

export function createEngagementPlanningFileTools(
  sessionRootPath: string,
  artifacts: EngagementPlanningArtifacts,
  store: EngagementStore,
  readOnlyArtifactPaths: readonly string[] = [],
) {
  const manifestLinesRead = new Set<number>();
  const readablePaths = new Set([
    artifacts.manifestPath,
    artifacts.planPath,
    ...readOnlyArtifactPaths.map((path) =>
      resolvedArtifactPath(sessionRootPath, path),
    ),
  ]);
  return {
    read_file: tool({
      description:
        "Read an authorized engagement planning artifact, including the immutable manifest, mutable plan, and sealed deployment preflight. Other filesystem paths are unavailable during planning.",
      inputSchema: z.object({
        path: z.string(),
        startLine: z.number().int().min(1).optional(),
        endLine: z.number().int().min(1).optional(),
        toolCallDescription: z.string(),
      }),
      execute: async ({ path, startLine, endLine }) => {
        const resolved = resolvedArtifactPath(sessionRootPath, path);
        if (!readablePaths.has(resolved)) {
          throw new Error(
            "Planning may only read authorized engagement planning artifacts",
          );
        }
        const lines = readFileSync(resolved, "utf8").split("\n");
        const start = startLine ?? 1;
        const requestedEnd = Math.min(endLine ?? lines.length, lines.length);
        const selected: string[] = [];
        let selectedLength = 0;
        for (let lineNumber = start; lineNumber <= requestedEnd; lineNumber++) {
          const line = `${String(lineNumber).padStart(6)}|${lines[lineNumber - 1] ?? ""}`;
          const nextLength = selectedLength + line.length + selected.length;
          if (nextLength > 100_000) break;
          selected.push(line);
          selectedLength += line.length;
          if (resolved === artifacts.manifestPath) {
            manifestLinesRead.add(lineNumber);
          }
        }
        if (
          resolved === artifacts.manifestPath &&
          manifestLinesRead.size === lines.length
        ) {
          store.recordInspectedTargets(
            store.snapshot().targets.map((target) => target.id),
          );
        }
        const content = selected.join("\n");
        return {
          success: true,
          error: "",
          content:
            start + selected.length - 1 < requestedEnd
              ? `${content}\n\n(truncated — continue at startLine ${start + selected.length})`
              : content,
          path,
          totalLines: lines.length,
          linesReturned: selected.length,
        };
      },
    }),
    create_file: tool({
      description:
        "Replace the external engagement plan artifact. The immutable manifest and all other filesystem paths are unavailable for writes.",
      inputSchema: z.object({
        path: z.string(),
        content: z.string(),
        overwrite: z.boolean().optional(),
        toolCallDescription: z.string(),
      }),
      execute: async ({ path, content, overwrite = false }) => {
        const resolved = resolvedArtifactPath(sessionRootPath, path);
        if (resolved !== artifacts.planPath) {
          throw new Error(
            "Planning may only write the engagement plan artifact",
          );
        }
        if (existsSync(resolved) && !overwrite) {
          return {
            success: false,
            error: `File already exists: ${path}. Set overwrite=true to replace it.`,
            path,
          };
        }
        atomicWrite(
          resolved,
          content.endsWith("\n") ? content : `${content}\n`,
        );
        return { success: true, error: "", path };
      },
    }),
  };
}

export function sealEngagementPlanArtifact(
  artifacts: EngagementPlanningArtifacts,
  store: EngagementStore,
): EngagementMissionState {
  const artifact = EngagementPlanArtifact.parse(
    JSON.parse(readFileSync(artifacts.planPath, "utf8")),
  );
  if (artifact.status !== "ready") {
    throw new Error("Set the engagement plan artifact status to ready");
  }
  if (artifact.contractHash !== artifacts.contractHash) {
    throw new Error("Engagement plan contractHash was changed");
  }

  if (artifact.version === 2) {
    const contextReads = store.snapshot().contextReads ?? {};
    const reviewedTargetIds = new Set(
      artifact.requirements.flatMap((requirement) =>
        requirement.coverage.map((association) => association.targetId),
      ),
    );
    const missingContext = [...reviewedTargetIds].filter((targetId) => {
      const receipt = contextReads[targetId];
      return receipt?.status !== "unavailable" && receipt?.complete !== true;
    });
    if (missingContext.length > 0) {
      throw new Error(
        `Review complete target context before sealing the canonical requirements: ${missingContext.join(", ")}`,
      );
    }
  }

  const previousCheckpoint = store.checkpoint();
  const previousMissions = store.snapshot().missions;
  store.saveMissions({
    planningStatus: "pending",
    inspectedTargetIds: previousMissions?.inspectedTargetIds,
    missions: [],
  });
  try {
    const definitions: Array<{
      mission: Omit<
        EngagementMission,
        "coverage" | "requirements" | "workerId" | "status" | "createdAt"
      >;
      requirements: EngagementMissionRequirement[];
    }> = [];
    if (artifact.version === 1) {
      for (const mission of artifact.missions) {
        definitions.push({ mission, requirements: mission.requirements });
      }
    } else {
      const requirementsById = new Map(
        artifact.requirements.map((requirement) => [
          requirement.id,
          requirement,
        ]),
      );
      for (const mission of artifact.missions) {
        const requirements = mission.requirementIds.map((id) => {
          const requirement = requirementsById.get(id);
          if (!requirement)
            throw new Error(`Unknown canonical requirement: ${id}`);
          return {
            id: requirement.id,
            description: requirement.description,
            rationale: requirement.rationale,
            equivalenceBasis: requirement.equivalenceBasis,
            prerequisiteCapabilityIds: requirement.prerequisiteCapabilityIds,
            nonConsolidationReason: requirement.nonConsolidationReason,
            coverage: requirement.coverage,
          };
        });
        definitions.push({
          mission: {
            id: mission.id,
            purpose: mission.purpose,
            rationale: mission.rationale,
            singletonJustification: mission.singletonJustification,
            supportingTargetIds: mission.supportingTargetIds,
            contextTargetIds: mission.contextTargetIds,
            prerequisiteMissionIds: mission.prerequisiteMissionIds,
            requiredActorRoles: mission.requiredActorRoles,
          },
          requirements,
        });
      }
    }
    for (const { mission, requirements } of definitions) {
      const coverage = requirements.flatMap(
        (requirement) => requirement.coverage,
      );
      store.defineMission({
        ...mission,
        requirements,
        coverage,
        workerId: newSessionId() as string,
        status: "planned",
        createdAt: new Date().toISOString(),
      });
    }
    const sealed = store.setMissionPlanningComplete();
    writeJson(artifacts.planPath, {
      ...artifact,
      status: "sealed",
      metrics: sealed.metrics,
    });
    return sealed;
  } catch (error) {
    store.restore(previousCheckpoint);
    throw error;
  }
}
