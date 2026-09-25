import { z } from "zod";

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

export interface DeploymentPrerequisiteDisposition {
  requirementId: string;
  status: "runnable" | "blocked" | "unknown";
  unavailableCapabilityIds: string[];
  unknownCapabilityIds: string[];
  evidence: string[];
  coverage: Array<{ targetId: string; objectiveId: string }>;
}
