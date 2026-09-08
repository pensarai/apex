import { tool } from "ai";
import { z } from "zod";
import { newSessionId } from "../id/id";
import type { EngagementCheckpoint, EngagementStore } from "./engagementState";

export const ENGAGEMENT_PLANNING_TOOL_NAMES = [
  "read_engagement_manifest",
  "define_engagement_mission",
  "delete_engagement_mission",
  "complete_engagement_mission_plan",
] as const;

export const ENGAGEMENT_PLANNING_PROMPT = `Plan coherent testing missions for this authorized engagement before testing begins.
Page through the entire read_engagement_manifest, search the attack surface, and read detailed threat models where useful. Group related endpoints by authentication, shared resources, and causal flow. Application code does not choose groups.
Define missions with exact target/objective obligations, rationale, context target references, supporting targets, and prerequisite mission IDs. Read each definition's returned ID before referencing it. Supporting/context targets do not earn coverage credit.
Every obligation must be assigned exactly once. Every singleton mission needs a justification. For eight or more targets, at most 25% of targets may have singleton missions and the plan must average at least two primary targets per mission. Keep missions bounded to 100 obligations. Edit or delete definitions to repair validation errors; never force unrelated endpoints together just to pass a gate. If a valid coherent plan is impossible, report the limitation.
Definitions do not launch workers. Call complete_engagement_mission_plan to validate and seal the plan, then response. No testing tools are available during planning.`;

export function createEngagementPlanningTools(
  store: EngagementStore,
  onCheckpoint?: (checkpoint: EngagementCheckpoint) => void | Promise<void>,
) {
  const persist = async (result: Record<string, unknown>) => {
    const checkpoint = store.checkpoint();
    await onCheckpoint?.(checkpoint);
    return { ...result, stateVersion: checkpoint.updatedAt };
  };
  return {
    read_engagement_manifest: tool({
      description:
        "Read a bounded page of the complete immutable target/objective contract and current mission definitions. Read every target before sealing.",
      inputSchema: z.object({
        offset: z.number().int().min(0).default(0),
        limit: z.number().int().min(1).max(25).default(10),
        toolCallDescription: z.string(),
      }),
      execute: async ({ offset, limit }) => {
        const state = store.snapshot();
        const targets = state.targets.slice(offset, offset + limit);
        store.recordInspectedTargets(targets.map((target) => target.id));
        return persist({
          targets: targets.map((target) => ({
            ...target,
            objectives: target.objectiveIds.map((id) => store.getObjective(id)),
          })),
          total: state.targets.length,
          offset,
          nextOffset:
            offset + targets.length < state.targets.length
              ? offset + targets.length
              : null,
          missions: state.missions?.missions.slice(offset, offset + limit),
          missionTotal: state.missions?.missions.length ?? 0,
        });
      },
    }),
    define_engagement_mission: tool({
      description:
        "Create or replace a planned mission; returns its stable ID. Does not create or start a worker.",
      inputSchema: z.object({
        missionId: z.string().optional(),
        purpose: z.string().min(1).max(4_000),
        rationale: z.string().min(1).max(4_000),
        singletonJustification: z.string().min(1).max(4_000).optional(),
        coverage: z
          .array(
            z.object({
              targetId: z.string().min(1),
              objectiveId: z.string().min(1),
            }),
          )
          .min(1)
          .max(100),
        supportingTargetIds: z.array(z.string()).max(100).default([]),
        contextTargetIds: z.array(z.string()).max(100).default([]),
        prerequisiteMissionIds: z.array(z.string()).max(100).default([]),
        toolCallDescription: z.string(),
      }),
      execute: async ({ missionId, toolCallDescription: _, ...definition }) => {
        const existing = missionId
          ? store
              .snapshot()
              .missions?.missions.find((mission) => mission.id === missionId)
          : undefined;
        if (missionId && !existing)
          throw new Error(`Unknown mission: ${missionId}`);
        const workerId = existing?.workerId ?? (newSessionId() as string);
        const id = missionId ?? `mission_${workerId}`;
        store.defineMission({
          ...definition,
          id,
          workerId,
          status: "planned",
          createdAt: existing?.createdAt ?? new Date().toISOString(),
        });
        return persist({ success: true, missionId: id });
      },
    }),
    delete_engagement_mission: tool({
      description:
        "Delete an unsealed planned mission. Repair any references before sealing.",
      inputSchema: z.object({
        missionId: z.string(),
        toolCallDescription: z.string(),
      }),
      execute: async ({ missionId }) => {
        store.deletePlannedMission(missionId);
        return persist({ success: true });
      },
    }),
    complete_engagement_mission_plan: tool({
      description:
        "Seal the complete model-created plan after exact coverage, grouping quality, and dependency validation. Workers are scheduled by the host after planning finishes.",
      inputSchema: z.object({ toolCallDescription: z.string() }),
      execute: async () => {
        const plan = store.setMissionPlanningComplete();
        return persist({
          success: true,
          missionCount: plan.missions.length,
          metrics: plan.metrics,
        });
      },
    }),
  };
}
