import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";

export const ENGAGEMENT_PREFLIGHT_RELATIVE_PATH =
  "coordination/engagement-preflight.json";

const DeploymentCapabilityStatus = z.enum([
  "available",
  "unavailable",
  "unknown",
]);

const DeploymentCapabilityKind = z.enum([
  "actor",
  "feature",
  "provider",
  "integration",
  "policy",
  "runtime-access",
]);

export const DeploymentCapability = z
  .object({
    id: z.string().min(1).max(120),
    kind: DeploymentCapabilityKind,
    label: z.string().min(1).max(1_000),
    status: DeploymentCapabilityStatus,
    targetIds: z.array(z.string().min(1)).max(1_000).default([]),
    evidence: z.array(z.string().min(1).max(4_000)).max(100).default([]),
    summary: z.string().min(1).max(10_000),
    observedAt: z.string().datetime(),
  })
  .superRefine((capability, context) => {
    if (capability.status !== "unknown" && capability.evidence.length === 0) {
      context.addIssue({
        code: "custom",
        message: `${capability.status} deployment capabilities require evidence`,
        path: ["evidence"],
      });
    }
  });

export type DeploymentCapability = z.infer<typeof DeploymentCapability>;

export const DeploymentPreflightArtifact = z
  .object({
    version: z.literal(1),
    status: z.enum(["draft", "ready", "sealed"]),
    contractHash: z.string().min(1),
    targetIds: z.array(z.string().min(1)),
    capabilities: z.array(DeploymentCapability),
    notes: z.string().max(100_000).optional(),
  })
  .superRefine((artifact, context) => {
    const targetIds = new Set(artifact.targetIds);
    if (targetIds.size !== artifact.targetIds.length) {
      context.addIssue({
        code: "custom",
        message: "Preflight target IDs must be unique",
        path: ["targetIds"],
      });
    }
    const capabilityIds = artifact.capabilities.map(
      (capability) => capability.id,
    );
    if (new Set(capabilityIds).size !== capabilityIds.length) {
      context.addIssue({
        code: "custom",
        message: "Deployment capability IDs must be unique",
        path: ["capabilities"],
      });
    }
    for (const [index, capability] of artifact.capabilities.entries()) {
      const unknownTargetIds = capability.targetIds.filter(
        (targetId) => !targetIds.has(targetId),
      );
      if (unknownTargetIds.length > 0) {
        context.addIssue({
          code: "custom",
          message: `Deployment capability scope contains unknown targets: ${unknownTargetIds.join(", ")}`,
          path: ["capabilities", index, "targetIds"],
        });
      }
    }
  });

export type DeploymentPreflightArtifact = z.infer<
  typeof DeploymentPreflightArtifact
>;

export interface DeploymentPreflightArtifacts {
  contractHash: string;
  path: string;
  relativePath: typeof ENGAGEMENT_PREFLIGHT_RELATIVE_PATH;
}

export interface DeploymentPrerequisiteRequirement {
  id: string;
  coverage: Array<{ targetId: string; objectiveId: string }>;
  prerequisiteCapabilityIds: string[];
}

export interface DeploymentPrerequisiteDisposition {
  requirementId: string;
  status: "runnable" | "blocked" | "unknown";
  unavailableCapabilityIds: string[];
  unknownCapabilityIds: string[];
  evidence: string[];
  coverage: Array<{ targetId: string; objectiveId: string }>;
}

function atomicWrite(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  renameSync(temporaryPath, path);
}

export function prepareDeploymentPreflightArtifact(
  sessionRootPath: string,
  input: {
    contractHash: string;
    targetIds: string[];
    capabilities?: DeploymentCapability[];
    status?: "draft" | "ready";
  },
): DeploymentPreflightArtifacts {
  const path = join(sessionRootPath, ENGAGEMENT_PREFLIGHT_RELATIVE_PATH);
  if (!existsSync(path)) {
    atomicWrite(path, {
      version: 1,
      status: input.status ?? "draft",
      contractHash: input.contractHash,
      targetIds: input.targetIds,
      capabilities: input.capabilities ?? [],
      notes: "",
    });
  }
  return {
    contractHash: input.contractHash,
    path,
    relativePath: ENGAGEMENT_PREFLIGHT_RELATIVE_PATH,
  };
}

export function sealDeploymentPreflightArtifact(
  artifacts: DeploymentPreflightArtifacts,
): DeploymentPreflightArtifact {
  const artifact = DeploymentPreflightArtifact.parse(
    JSON.parse(readFileSync(artifacts.path, "utf8")),
  );
  if (artifact.contractHash !== artifacts.contractHash) {
    throw new Error("Deployment preflight contractHash was changed");
  }
  if (artifact.status !== "ready") {
    if (artifact.status === "sealed") return artifact;
    throw new Error("Set the deployment preflight artifact status to ready");
  }
  const sealed = { ...artifact, status: "sealed" as const };
  atomicWrite(artifacts.path, sealed);
  return sealed;
}

export function evaluateDeploymentPrerequisites(
  requirements: DeploymentPrerequisiteRequirement[],
  artifact: DeploymentPreflightArtifact,
): DeploymentPrerequisiteDisposition[] {
  if (artifact.status !== "sealed") {
    throw new Error("Deployment prerequisites require a sealed preflight");
  }
  const requirementIds = requirements.map((requirement) => requirement.id);
  if (new Set(requirementIds).size !== requirementIds.length) {
    throw new Error("Deployment prerequisite requirement IDs must be unique");
  }
  const capabilities = new Map(
    artifact.capabilities.map((capability) => [capability.id, capability]),
  );
  return requirements.map((requirement) => {
    const uniqueCapabilityIds = [
      ...new Set(requirement.prerequisiteCapabilityIds),
    ];
    if (
      uniqueCapabilityIds.length !==
      requirement.prerequisiteCapabilityIds.length
    ) {
      throw new Error(
        `Requirement ${requirement.id} contains duplicate deployment prerequisites`,
      );
    }
    const resolved = uniqueCapabilityIds.map((id) => {
      const capability = capabilities.get(id);
      if (!capability) {
        throw new Error(
          `Requirement ${requirement.id} references unknown deployment capability ${id}`,
        );
      }
      return capability;
    });
    const requirementTargetIds = new Set(
      requirement.coverage.map((association) => association.targetId),
    );
    for (const capability of resolved) {
      if (capability.targetIds.length === 0) continue;
      const scopedTargetIds = new Set(capability.targetIds);
      const outsideScope = [...requirementTargetIds].filter(
        (targetId) => !scopedTargetIds.has(targetId),
      );
      if (outsideScope.length > 0) {
        throw new Error(
          `Deployment capability ${capability.id} is outside requirement ${requirement.id} scope for targets: ${outsideScope.join(", ")}`,
        );
      }
    }
    const unavailable = resolved.filter(
      (capability) => capability.status === "unavailable",
    );
    const unknown = resolved.filter(
      (capability) => capability.status === "unknown",
    );
    return {
      requirementId: requirement.id,
      status:
        unavailable.length > 0
          ? ("blocked" as const)
          : unknown.length > 0
            ? ("unknown" as const)
            : ("runnable" as const),
      unavailableCapabilityIds: unavailable.map((capability) => capability.id),
      unknownCapabilityIds: unknown.map((capability) => capability.id),
      evidence: unavailable.flatMap((capability) =>
        capability.evidence.map(
          (evidence) => `deployment-preflight:${capability.id}:${evidence}`,
        ),
      ),
      coverage: requirement.coverage,
    };
  });
}
