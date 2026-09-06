import { z } from "zod";
import type { AIModel } from "../ai";
import type { PentestWorkflowInput } from "./pentest";

export interface EngagementModelConfig {
  model: AIModel;
  enableThinking?: boolean;
  thinkingEffort?: PentestWorkflowInput["thinkingEffort"];
  openAIReasoningEffort?: PentestWorkflowInput["openAIReasoningEffort"];
}

export interface EngagementMissionCoverage {
  targetId: string;
  objectiveId: string;
}

export interface EngagementMission {
  id: string;
  workerId: string;
  purpose: string;
  rationale: string;
  coverage: EngagementMissionCoverage[];
  supportingTargetIds: string[];
  prerequisiteMissionIds: string[];
  contextTargetIds: string[];
  status: "queued" | "running" | "completed" | "failed";
  createdAt: string;
  completedAt?: string;
}

export interface EngagementMissionState {
  planningStatus: "pending" | "partial" | "complete";
  missions: EngagementMission[];
}

export const GroupedMissionResult = z.object({
  summary: z.string().min(1).max(20_000),
  obligationResults: z
    .array(
      z.object({
        targetId: z.string().min(1),
        objectiveId: z.string().min(1),
        status: z.enum(["impact-proven", "exhausted", "blocked"]),
        summary: z.string().min(1).max(10_000),
        evidence: z
          .array(
            z.object({
              description: z.string().min(1),
              toolCallId: z.string().min(1),
              toolName: z.string().min(1),
            }),
          )
          .max(20)
          .default([]),
      }),
    )
    .max(100),
});

export type GroupedMissionOutcome = z.infer<typeof GroupedMissionResult>;

export const GROUPED_MISSION_SYSTEM_PROMPT = `You are a focused penetration-test mission worker inside one authorized engagement. Test the related endpoint flow as a system, preserving cookies, authentication state, and causal context across the mission.

You own only the explicit coverage obligations in the mission contract. Supporting targets are context and may be exercised, but do not create coverage credit. For every obligation, return exactly one result: impact-proven only with trace-linked successful evidence, exhausted only after meaningful bounded testing, or blocked with the concrete prerequisite that prevented testing. Never mark an obligation tested merely because a related endpoint was tested.

Discover and validate net-new vulnerabilities and multi-step paths while executing the assigned flow. Document only reproducible exploitable findings through the shared finding judge. All network and finding tools enforce the engagement's authorized scope.`;

export function applyEngagementModel(
  workflow: PentestWorkflowInput,
  config: EngagementModelConfig | undefined,
): PentestWorkflowInput {
  if (!config) return workflow;
  return {
    ...workflow,
    model: config.model,
    enableThinking: config.enableThinking,
    thinkingEffort: config.thinkingEffort,
    openAIReasoningEffort: config.openAIReasoningEffort,
  };
}

export function engagementModelFromWorkflow(
  workflow: PentestWorkflowInput,
): EngagementModelConfig {
  return {
    model: workflow.model,
    enableThinking: workflow.enableThinking,
    thinkingEffort: workflow.thinkingEffort,
    openAIReasoningEffort: workflow.openAIReasoningEffort,
  };
}
