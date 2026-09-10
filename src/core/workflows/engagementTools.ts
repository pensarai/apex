import type { ModelMessage, ToolSet } from "ai";
import { tool } from "ai";
import { z } from "zod";
import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { TargetedPentestAgent } from "../agents/specialized/pentest/agent";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import { newSessionId } from "../id/id";
import { loadSubagentMessages, saveSubagentData } from "../session/persistence";
import {
  applyEngagementModel,
  type EngagementMission,
  type EngagementMissionCoverage,
  type EngagementModelConfig,
  GROUPED_MISSION_SYSTEM_PROMPT,
  GroupedMissionCoverageBatch,
  GroupedMissionResult,
} from "./engagementMissions";
import {
  AgentMailbox,
  type EngagementCheckpoint,
  type EngagementStore,
  type EngagementWorkerMode,
} from "./engagementState";
import { EngagementWorkerPool } from "./engagementWorkerPool";
import { runFastStrikeObjective } from "./fastStrike";
import { FastStrikeEvidenceLedger } from "./fastStrikeEvidence";
import type { PentestWorkflowInput } from "./pentest";

const COVERAGE_STATUSES = [
  "pending",
  "assigned",
  "running",
  "needs-lead",
  "impact-proven",
  "exhausted",
  "blocked",
] as const;
const SERVICE_STATUSES = ["pending", "running", "explored", "blocked"] as const;
const CHAIN_STATUSES = [
  "pending",
  "running",
  "impact-proven",
  "exhausted",
  "blocked",
] as const;
const WORKER_MODES = [
  "targeted",
  "fast-strike",
  "grouped",
  "explore",
  "chain",
] as const;

export const ENGAGEMENT_TOOL_NAMES = [
  "read_engagement_state",
  "spawn_engagement_worker",
  "follow_up_engagement_worker",
  "send_engagement_worker_message",
  "wait_for_engagement_workers",
  "update_engagement_coverage",
  "record_engagement_capability",
  "record_impact_proof",
] as const;

interface EngagementToolRuntime {
  input: PentestWorkflowInput;
  workerModel?: EngagementModelConfig;
  store: EngagementStore;
  findingsRegistry: FindingsRegistry;
  eventBus: AgentEventBus;
  leadAgentId: string;
  surfaceTools?: ToolSet;
  engagementTargetIds?: string[];
  workerPool?: EngagementWorkerPool;
  onWorkerJob?: (job: Promise<unknown>) => void;
  onCheckpoint?: (checkpoint: EngagementCheckpoint) => void | Promise<void>;
}

export function formatEngagementError(error: unknown): string {
  if (error instanceof Error) {
    const cause = error.cause ? `: ${formatEngagementError(error.cause)}` : "";
    return `${error.message || error.name}${cause}`;
  }
  if (typeof error === "string") return error;
  try {
    const serialized = JSON.stringify(error, (_key, value) =>
      value instanceof Error
        ? { name: value.name, message: value.message, cause: value.cause }
        : value,
    );
    if (serialized && serialized !== "{}") return serialized;
  } catch {
    // Fall through to the stable generic description.
  }
  return "Unknown engagement worker error";
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function buildWorkerContext(
  store: EngagementStore,
  mission: string,
  serviceIds: string[],
  targetIds: string[],
  objectiveIds: string[],
  capabilityIds: string[],
): string {
  const state = store.snapshot();
  const services = serviceIds.map((id) => store.getService(id));
  const objectives = objectiveIds.map((id) => store.getObjective(id));
  const targets = targetIds.map((id) => store.getTarget(id));
  const capabilities = capabilityIds.map((id) => store.getCapability(id));
  return [
    `Mission: ${mission}`,
    state.operatorContext
      ? `Engagement context:\n${state.operatorContext}`
      : "",
    `Assigned services:\n${services
      .map(
        (service) =>
          `- ${service.id}: ${service.origin}\n  Targets: ${service.targets.join(", ")}`,
      )
      .join("\n")}`,
    `Assigned targets:\n${targets
      .map((target) => `- ${target.id}: ${target.target}`)
      .join("\n")}`,
    objectives.length > 0
      ? `Assigned objective IDs:\n${objectives
          .map((objective) => `- ${objective.id}: ${objective.text}`)
          .join("\n")}`
      : "",
    capabilities.length > 0
      ? `Assigned capabilities:\n${capabilities
          .map(
            (capability) =>
              `- ${capability.id}: ${capability.label}\n  ${capability.description}\n  Next steps: ${capability.nextSteps.join(", ") || "none"}`,
          )
          .join("\n")}`
      : "",
    "Preserve concrete observations and reusable primitives in your final summary. Do not treat this assignment as engagement completion.",
  ]
    .filter(Boolean)
    .join("\n\n");
}

function validateAssignment(
  store: EngagementStore,
  mode: EngagementWorkerMode,
  serviceIds: string[],
  targetIds: string[],
  objectiveIds: string[],
  capabilityIds: string[],
): void {
  if (serviceIds.length === 0)
    throw new Error("At least one serviceId is required");
  for (const serviceId of serviceIds) store.getService(serviceId);
  for (const targetId of targetIds) {
    const target = store.getTarget(targetId);
    if (!serviceIds.includes(target.serviceId)) {
      throw new Error(
        `Target ${targetId} is not part of the selected services`,
      );
    }
  }
  for (const objectiveId of objectiveIds) {
    const objective = store.getObjective(objectiveId);
    if (!objective.relevantServiceIds.some((id) => serviceIds.includes(id))) {
      throw new Error(
        `Objective ${objectiveId} is not relevant to the selected services`,
      );
    }
    if (mode === "targeted" || mode === "fast-strike" || mode === "grouped") {
      for (const targetId of targetIds) {
        const coverage = store
          .snapshot()
          .coverage.find(
            (candidate) =>
              candidate.targetId === targetId &&
              candidate.objectiveId === objectiveId,
          );
        if (coverage?.status === "running") {
          throw new Error(
            `Coverage ${targetId}:${objectiveId} is already running`,
          );
        }
      }
    }
  }
  for (const capabilityId of capabilityIds) store.getCapability(capabilityId);
  if (
    mode === "fast-strike" &&
    (serviceIds.length !== 1 ||
      targetIds.length !== 1 ||
      objectiveIds.length !== 1)
  ) {
    throw new Error(
      "Fast Strike workers require exactly one service, target, and objective",
    );
  }
  if (
    (mode === "targeted" || mode === "grouped") &&
    objectiveIds.length === 0
  ) {
    throw new Error("Targeted workers require at least one objectiveId");
  }
  if (mode === "chain" && capabilityIds.length === 0) {
    throw new Error("Chain workers require at least one capabilityId");
  }
}

const WorkerAssignmentSchema = z.object({
  mission: z.string().min(1).max(4_000),
  serviceIds: z.array(z.string()).min(1).max(100),
  targetIds: z.array(z.string()).min(1).max(100),
  objectiveIds: z.array(z.string()).max(100).default([]),
  capabilityIds: z.array(z.string()).max(100).default([]),
  rationale: z.string().min(1).max(4_000).optional(),
  coverage: z
    .array(
      z.object({
        targetId: z.string().min(1),
        objectiveId: z.string().min(1),
      }),
    )
    .max(100)
    .optional(),
  supportingTargetIds: z.array(z.string()).max(100).default([]),
  prerequisiteMissionIds: z.array(z.string()).max(100).default([]),
  contextTargetIds: z.array(z.string()).max(100).default([]),
  mode: z.enum(WORKER_MODES),
  toolCallDescription: z.string(),
});
type WorkerAssignment = z.infer<typeof WorkerAssignmentSchema>;

export function createEngagementTools(runtime: EngagementToolRuntime) {
  const {
    input,
    workerModel,
    store,
    findingsRegistry,
    eventBus,
    leadAgentId,
    surfaceTools,
    engagementTargetIds = [],
    workerPool = new EngagementWorkerPool(4),
    onWorkerJob,
    onCheckpoint,
  } = runtime;
  const mailbox = new AgentMailbox(input.session.rootPath);
  const activeWorkers = new Set<string>();
  const workerJobs = new Map<string, Promise<Record<string, unknown>>>();
  const boundedCompletion = () => {
    const completion = store.completion();
    return {
      ...completion,
      missingObjectiveIds: completion.missingObjectiveIds.slice(0, 100),
      missingCoverageCellIds: completion.missingCoverageCellIds.slice(0, 100),
      missingServiceIds: completion.missingServiceIds.slice(0, 100),
      unresolvedCapabilityIds: completion.unresolvedCapabilityIds.slice(0, 100),
      activeMissionIds: completion.activeMissionIds.slice(0, 100),
    };
  };
  const withCheckpoint = async <T extends Record<string, unknown>>(
    result: T,
  ) => {
    const checkpoint = store.checkpoint();
    await onCheckpoint?.(checkpoint);
    return {
      ...result,
      stateVersion: checkpoint.updatedAt,
      completion: boundedCompletion(),
    };
  };

  const runWorker = async (options: {
    workerId: string;
    mission: string;
    mode: EngagementWorkerMode;
    serviceIds: string[];
    targetIds: string[];
    objectiveIds: string[];
    capabilityIds: string[];
    missionId?: string;
    coverage?: EngagementMissionCoverage[];
    messages?: ModelMessage[];
    followUp?: boolean;
  }) => {
    if (activeWorkers.has(options.workerId)) {
      throw new Error(`Worker ${options.workerId} is already running`);
    }
    activeWorkers.add(options.workerId);
    let latestMessages: ModelMessage[] = [];
    let lastTarget = input.target;
    try {
      if (!options.followUp) store.startWorker(options.workerId);
      if (options.missionId)
        store.setMissionStatus(options.missionId, "running");
      if (options.mode === "grouped" && !options.followUp) {
        const claimed = store.claimCoverageCells({
          workerId: options.workerId,
          cells: options.coverage ?? [],
        });
        if (claimed.length !== (options.coverage ?? []).length) {
          throw new Error("Failed to claim grouped mission coverage");
        }
      }
      if (options.followUp) {
        store.restartWorker(options.workerId);
        if (options.mode === "explore") {
          for (const serviceId of options.serviceIds) {
            store.markServiceBaseline(serviceId, "running", options.mission);
          }
        } else if (options.mode === "grouped") {
          const pending = (options.coverage ?? []).filter((cell) =>
            store
              .snapshot()
              .coverage.some(
                (candidate) =>
                  candidate.targetId === cell.targetId &&
                  candidate.objectiveId === cell.objectiveId &&
                  candidate.status === "pending",
              ),
          );
          const claimed = store.claimCoverageCells({
            workerId: options.workerId,
            cells: pending,
          });
          if (claimed.length !== pending.length) {
            throw new Error("Failed to reclaim interrupted grouped coverage");
          }
        } else {
          for (const objectiveId of options.objectiveIds) {
            for (const targetId of options.targetIds) {
              const target = store.getTarget(targetId);
              if (!target.objectiveIds.includes(objectiveId)) continue;
              store.markObjectiveCoverage({
                targetId,
                objectiveId,
                serviceId: target.serviceId,
                status: "running",
                workerId: options.workerId,
                summary: options.mission,
              });
            }
          }
        }
      }
      const services = options.serviceIds.map((id) => store.getService(id));
      const objectives = options.objectiveIds.map((id) =>
        store.getObjective(id),
      );
      const targets = options.targetIds.map((id) => store.getTarget(id));
      const workerWorkflow =
        options.mode === "chain"
          ? input
          : applyEngagementModel(input, workerModel);
      const target =
        targets[0]?.target ?? services[0]?.targets[0] ?? input.target;
      lastTarget = target;
      const context = buildWorkerContext(
        store,
        options.mission,
        options.serviceIds,
        options.targetIds,
        options.objectiveIds,
        options.capabilityIds,
      );
      const childBus = new AgentEventBus();
      AgentEventBus.attachChild(childBus, eventBus, options.workerId);
      eventBus.emit("subagent-spawn", {
        subagentId: options.workerId,
        sessionId: options.workerId,
        name: options.followUp
          ? `Follow-up: ${options.mission.slice(0, 70)}`
          : options.mission.slice(0, 80),
        input: {
          mission: options.mission,
          mode: options.mode,
          serviceIds: options.serviceIds,
          targetIds: options.targetIds,
          objectiveIds: options.objectiveIds,
          capabilityIds: options.capabilityIds,
        },
        parentSubagentId: leadAgentId,
        parentSessionId: leadAgentId,
      });

      const handleStepFinish = (
        event: Parameters<NonNullable<PentestWorkflowInput["onStepFinish"]>>[0],
      ) => {
        if (event.response.messages) latestMessages = event.response.messages;
        input.onStepFinish?.(event);
      };
      let summary: string;
      let result: Record<string, unknown>;
      if (options.mode === "fast-strike") {
        const objective = objectives[0];
        if (!objective) throw new Error("Fast Strike objective is missing");
        const outcome = await runFastStrikeObjective({
          ...workerWorkflow,
          target,
          objective: `${objective.text}\n\n${context}`,
          messages: options.messages,
          findingsRegistry,
          eventBus: childBus,
          onStepFinish: handleStepFinish,
          laneCount: 1,
          singleLaneId: options.workerId,
          subagentPrefix: options.workerId,
          sandbox: input.sandbox,
          secretValues: input.secretValues,
          display: input.display,
          extraTools: surfaceTools,
          directTools: surfaceTools ? Object.keys(surfaceTools) : undefined,
          engagementTargetIds,
        });
        summary = outcome.summary;
        result = {
          status: outcome.status,
          summary,
          evidence: outcome.evidence ?? [],
          findings: outcome.findings,
        };
        store.markObjectiveCoverage({
          targetId: targets[0]?.id as string,
          objectiveId: objective.id,
          serviceId: services[0]?.id as string,
          status: outcome.status,
          workerId: options.workerId,
          summary,
          evidence: (outcome.evidence ?? []).map(
            (reference) => `${reference.toolName}:${reference.toolCallId}`,
          ),
        });
      } else if (options.mode === "grouped") {
        const assigned = options.coverage ?? [];
        const evidenceLedger = new FastStrikeEvidenceLedger(childBus);
        try {
          const expected = new Set(
            assigned.map((cell) => `${cell.targetId}:${cell.objectiveId}`),
          );
          const reportCoverage = tool({
            description:
              "Durably record completed coverage obligations in batches. Call this as testing progresses so results survive a later worker interruption.",
            inputSchema: GroupedMissionCoverageBatch,
            execute: async ({ obligationResults }) => {
              const returned = obligationResults.map(
                (cell) => `${cell.targetId}:${cell.objectiveId}`,
              );
              if (
                new Set(returned).size !== returned.length ||
                returned.some((cell) => !expected.has(cell))
              ) {
                throw new Error(
                  "Coverage reports must contain unique obligations from this mission contract",
                );
              }
              for (const obligation of obligationResults) {
                if (obligation.status === "impact-proven") {
                  const rejection = evidenceLedger.validateImpactEvidence(
                    obligation.evidence,
                    new Set([options.workerId]),
                  );
                  if (rejection) throw new Error(rejection);
                }
                const settled = store.settleCoverageCell({
                  targetId: obligation.targetId,
                  objectiveId: obligation.objectiveId,
                  workerId: options.workerId,
                  status: obligation.status,
                  summary: obligation.summary,
                  evidence: obligation.evidence.map(
                    (reference) =>
                      `${reference.toolName}:${reference.toolCallId}`,
                  ),
                });
                if (!settled) {
                  throw new Error(
                    `Worker no longer owns coverage ${obligation.targetId}:${obligation.objectiveId}`,
                  );
                }
              }
              const remaining = store
                .snapshot()
                .coverage.filter(
                  (cell) =>
                    cell.workerId === options.workerId &&
                    cell.status === "running" &&
                    expected.has(`${cell.targetId}:${cell.objectiveId}`),
                )
                .map((cell) => ({
                  targetId: cell.targetId,
                  objectiveId: cell.objectiveId,
                }));
              return withCheckpoint({
                success: true,
                recorded: obligationResults.length,
                remaining,
              });
            },
          });
          const agent = new OffensiveSecurityAgent({
            system: GROUPED_MISSION_SYSTEM_PROMPT,
            prompt: [
              `Mission: ${options.mission}`,
              "Coverage contract:",
              JSON.stringify(assigned),
              "Authorized target and threat-model context:",
              context,
            ].join("\n\n"),
            model: workerWorkflow.model,
            session: input.session,
            target,
            mode: "fast-strike",
            activeTools: ["report_engagement_coverage"],
            extraTools: {
              ...surfaceTools,
              report_engagement_coverage: reportCoverage,
            },
            directTools: [
              ...(surfaceTools ? Object.keys(surfaceTools) : []),
              "report_engagement_coverage",
            ],
            engagementTargetIds,
            responseSchema: GroupedMissionResult,
            responseGuard: (candidate) => {
              const parsed = GroupedMissionResult.safeParse(candidate);
              if (!parsed.success) return "Return a concise mission summary.";
              const remaining = store
                .snapshot()
                .coverage.filter(
                  (cell) =>
                    cell.workerId === options.workerId &&
                    cell.status === "running" &&
                    expected.has(`${cell.targetId}:${cell.objectiveId}`),
                );
              if (remaining.length > 0)
                return `Report the ${remaining.length} remaining coverage obligations before responding.`;
              return undefined;
            },
            findingsRegistry,
            messages: options.messages,
            subagentId: options.workerId,
            subagentName: options.mission.slice(0, 80),
            authConfig: input.authConfig,
            abortSignal: input.abortSignal,
            eventBus: childBus,
            onStepFinish: handleStepFinish,
            getPendingMessages: async () =>
              mailbox.take(options.workerId).map((message) => ({
                role: "user" as const,
                content: [
                  {
                    type: "text" as const,
                    text: `Directed message from engagement lead: ${message.payload}`,
                  },
                ],
              })),
            enableThinking: workerWorkflow.enableThinking,
            thinkingEffort: workerWorkflow.thinkingEffort,
            openAIReasoningEffort: workerWorkflow.openAIReasoningEffort,
            toolProtocol: input.toolProtocol,
            environmentVariables: input.environmentVariables,
            secretValues: input.secretValues,
            sandbox: input.sandbox,
            display: input.display,
          });
          const outcome = GroupedMissionResult.parse(await agent.consume());
          summary = outcome.summary;
          result = outcome;
        } finally {
          evidenceLedger.dispose();
        }
      } else {
        const agent = new TargetedPentestAgent({
          target,
          objectives:
            objectives.length > 0
              ? objectives.map((objective) => objective.text)
              : [options.mission],
          context,
          model: workerWorkflow.model,
          session: input.session,
          authConfig: input.authConfig,
          abortSignal: input.abortSignal,
          findingsRegistry,
          eventBus: childBus,
          subagentId: options.workerId,
          subagentName: options.mission.slice(0, 80),
          messages: options.messages,
          onStepFinish: handleStepFinish,
          enableThinking: workerWorkflow.enableThinking,
          thinkingEffort: workerWorkflow.thinkingEffort,
          openAIReasoningEffort: workerWorkflow.openAIReasoningEffort,
          environmentVariables: input.environmentVariables,
          secretValues: input.secretValues,
          sandbox: input.sandbox,
          display: input.display,
          role: "worker",
          toolProtocol: input.toolProtocol,
          extraTools: surfaceTools,
          directTools: surfaceTools ? Object.keys(surfaceTools) : undefined,
          engagementTargetIds,
        });
        const outcome = await agent.consume();
        summary =
          outcome.objectiveResults
            ?.map(
              (objective) =>
                `${objective.objective}: ${objective.completed ? "completed" : "incomplete"}${objective.result ? ` — ${objective.result}` : ""}`,
            )
            .join("\n") ||
          `Worker completed with ${outcome.findings.length} finding(s).`;
        result = {
          summary,
          objectiveResults: outcome.objectiveResults ?? [],
          findingsCount: outcome.findings.length,
        };
        if (options.mode === "explore") {
          for (const service of services) {
            store.markServiceBaseline(service.id, "explored", summary);
          }
        } else if (options.mode === "targeted") {
          for (const objective of objectives) {
            const objectiveResult = outcome.objectiveResults?.find(
              (candidate) => candidate.objective === objective.text,
            );
            for (const targetRecord of targets.filter((candidate) =>
              candidate.objectiveIds.includes(objective.id),
            )) {
              store.markObjectiveCoverage({
                targetId: targetRecord.id,
                objectiveId: objective.id,
                serviceId: targetRecord.serviceId,
                status: objectiveResult?.completed ? "exhausted" : "blocked",
                workerId: options.workerId,
                summary: objectiveResult?.result ?? summary,
              });
            }
          }
        }
      }

      store.completeWorker(options.workerId, "completed", summary);
      if (options.missionId)
        store.setMissionStatus(options.missionId, "completed");
      mailbox.send({
        type: "FINAL_ANSWER",
        recipientAgentId: leadAgentId,
        senderAgentId: options.workerId,
        taskName: options.mission,
        payload: summary,
        status: "completed",
      });
      saveSubagentData(input.session, {
        agentName: options.workerId,
        target,
        objective: options.mission,
        status: "completed",
        messages: [...(options.messages ?? []), ...latestMessages],
        findingsCount: findingsRegistry.getFindings().length,
      });
      eventBus.emit("subagent-complete", {
        subagentId: options.workerId,
        sessionId: options.workerId,
        status: "completed",
        parentSubagentId: leadAgentId,
        parentSessionId: leadAgentId,
      });
      return withCheckpoint({
        success: true,
        workerId: options.workerId,
        ...result,
      });
    } catch (error) {
      const summary = formatEngagementError(error);
      const unfinishedCoverage = store
        .snapshot()
        .coverage.filter(
          (coverage) =>
            coverage.workerId === options.workerId &&
            coverage.status === "running",
        );
      if (options.mode === "grouped" && unfinishedCoverage.length === 0) {
        const recoveredSummary = `All assigned coverage was recorded before the result stream ended: ${summary}`;
        store.completeWorker(options.workerId, "completed", recoveredSummary);
        if (options.missionId)
          store.setMissionStatus(options.missionId, "completed");
        mailbox.send({
          type: "FINAL_ANSWER",
          recipientAgentId: leadAgentId,
          senderAgentId: options.workerId,
          taskName: options.mission,
          payload: recoveredSummary,
          status: "completed",
        });
        saveSubagentData(input.session, {
          agentName: options.workerId,
          target: lastTarget,
          objective: options.mission,
          status: "completed",
          messages: [...(options.messages ?? []), ...latestMessages],
          findingsCount: findingsRegistry.getFindings().length,
        });
        eventBus.emit("subagent-complete", {
          subagentId: options.workerId,
          sessionId: options.workerId,
          status: "completed",
          parentSubagentId: leadAgentId,
          parentSessionId: leadAgentId,
        });
        return withCheckpoint({
          success: true,
          recovered: true,
          workerId: options.workerId,
          summary: recoveredSummary,
        });
      }
      for (const coverage of store.snapshot().coverage) {
        if (
          coverage.workerId === options.workerId &&
          coverage.status === "running"
        ) {
          store.markObjectiveCoverage({
            targetId: coverage.targetId,
            objectiveId: coverage.objectiveId,
            serviceId: coverage.serviceId,
            status: "needs-lead",
            workerId: null,
            summary,
          });
        }
      }
      store.completeWorker(options.workerId, "failed", summary);
      if (options.missionId)
        store.setMissionStatus(options.missionId, "failed");
      mailbox.send({
        type: "FINAL_ANSWER",
        recipientAgentId: leadAgentId,
        senderAgentId: options.workerId,
        taskName: options.mission,
        payload: summary,
        status: "failed",
      });
      eventBus.emit("subagent-complete", {
        subagentId: options.workerId,
        sessionId: options.workerId,
        status: "failed",
        parentSubagentId: leadAgentId,
        parentSessionId: leadAgentId,
      });
      return withCheckpoint({
        success: false,
        workerId: options.workerId,
        message: summary,
      });
    } finally {
      activeWorkers.delete(options.workerId);
    }
  };

  const dispatchWorker = async (
    {
      mission,
      serviceIds,
      targetIds,
      objectiveIds,
      capabilityIds,
      rationale,
      coverage,
      supportingTargetIds,
      contextTargetIds,
      mode,
    }: WorkerAssignment,
    plannedMission?: EngagementMission,
  ) => {
    const configuredMode = input.session.config?.engagementCoverageMode;
    if (
      configuredMode === "grouped" &&
      (mode === "targeted" || mode === "fast-strike")
    ) {
      throw new Error(
        "Grouped coverage requires mode=grouped with explicit coverage obligations",
      );
    }
    if (mode === "grouped" && configuredMode !== "grouped") {
      throw new Error("Grouped workers require grouped engagement coverage");
    }
    const selectedServiceIds = unique(serviceIds);
    const selectedCoverage = coverage ?? [];
    const selectedTargetIds = unique([
      ...targetIds,
      ...(supportingTargetIds ?? []),
      ...(contextTargetIds ?? []),
      ...selectedCoverage.map((cell) => cell.targetId),
    ]);
    const selectedObjectiveIds = unique(objectiveIds);
    const selectedCapabilityIds = unique(capabilityIds);
    validateAssignment(
      store,
      mode,
      selectedServiceIds,
      selectedTargetIds,
      selectedObjectiveIds,
      selectedCapabilityIds,
    );
    if (mode === "grouped") {
      if (!rationale || selectedCoverage.length === 0) {
        throw new Error(
          "Grouped missions require rationale and explicit coverage obligations",
        );
      }
      const uniqueCells = new Set(
        selectedCoverage.map((cell) => `${cell.targetId}:${cell.objectiveId}`),
      );
      if (uniqueCells.size !== selectedCoverage.length) {
        throw new Error("Grouped mission coverage contains duplicates");
      }
      for (const cell of selectedCoverage) {
        const targetRecord = store.getTarget(cell.targetId);
        if (!targetRecord.objectiveIds.includes(cell.objectiveId)) {
          throw new Error(
            `Objective ${cell.objectiveId} is not assigned to target ${cell.targetId}`,
          );
        }
        if (!selectedObjectiveIds.includes(cell.objectiveId)) {
          throw new Error(
            `Coverage objective ${cell.objectiveId} is missing from objectiveIds`,
          );
        }
        const coverageCell = store
          .snapshot()
          .coverage.find(
            (candidate) =>
              candidate.targetId === cell.targetId &&
              candidate.objectiveId === cell.objectiveId,
          );
        if (
          coverageCell?.status !== "pending" &&
          coverageCell?.status !== "assigned"
        ) {
          throw new Error(
            `Coverage ${cell.targetId}:${cell.objectiveId} is already assigned or terminal`,
          );
        }
      }
    }
    const workerId = plannedMission?.workerId ?? (newSessionId() as string);
    const existingWorker = store
      .snapshot()
      .workers.find((worker) => worker.id === workerId);
    if (!existingWorker)
      store.registerWorker({
        id: workerId,
        mission,
        mode,
        serviceIds: selectedServiceIds,
        targetIds: selectedTargetIds,
        objectiveIds: selectedObjectiveIds,
        capabilityIds: selectedCapabilityIds,
        model:
          mode === "chain"
            ? {
                model: input.model,
                enableThinking: input.enableThinking,
                thinkingEffort: input.thinkingEffort,
                openAIReasoningEffort: input.openAIReasoningEffort,
              }
            : workerModel,
      });
    const missionId = plannedMission?.id;
    if (mode === "explore") {
      for (const serviceId of selectedServiceIds) {
        store.markServiceBaseline(serviceId, "running", mission);
      }
    } else if (mode === "grouped") {
      // Coverage is claimed only after scheduler admission.
    } else {
      for (const objectiveId of selectedObjectiveIds) {
        for (const targetId of selectedTargetIds) {
          const target = store.getTarget(targetId);
          if (!target.objectiveIds.includes(objectiveId)) continue;
          store.markObjectiveCoverage({
            targetId,
            objectiveId,
            serviceId: target.serviceId,
            status: "running",
            workerId,
            summary: mission,
          });
        }
      }
    }
    const run = () =>
      workerPool.run(mode === "chain" ? "chain" : "baseline", () =>
        runWorker({
          workerId,
          mission,
          mode,
          serviceIds: selectedServiceIds,
          targetIds: selectedTargetIds,
          objectiveIds: selectedObjectiveIds,
          capabilityIds: selectedCapabilityIds,
          missionId,
          coverage: selectedCoverage,
          messages: existingWorker
            ? loadSubagentMessages(input.session, workerId)
            : undefined,
        }),
      );
    const job = run();
    if (mode !== "grouped") return job;
    const resilientJob = job.catch(async (error) => {
      const summary = formatEngagementError(error);
      const worker = store
        .snapshot()
        .workers.find((candidate) => candidate.id === workerId);
      if (worker?.status === "running") {
        for (const cell of store.snapshot().coverage) {
          if (cell.workerId !== workerId || cell.status !== "running") continue;
          store.markObjectiveCoverage({
            targetId: cell.targetId,
            objectiveId: cell.objectiveId,
            serviceId: cell.serviceId,
            status: "needs-lead",
            workerId: null,
            summary,
          });
        }
        store.completeWorker(workerId, "failed", summary);
        if (missionId) store.setMissionStatus(missionId, "failed");
      }
      return withCheckpoint({ success: false, workerId, message: summary });
    });
    const tracked = resilientJob.finally(() => workerJobs.delete(workerId));
    workerJobs.set(workerId, tracked);
    onWorkerJob?.(tracked);
    return withCheckpoint({
      success: true,
      accepted: true,
      missionId,
      workerId,
    });
  };

  const tools = {
    ...surfaceTools,
    read_engagement_state: tool({
      description:
        "Read a compact page of persisted engagement services, objectives, and coverage plus high-signal capabilities, impact proofs, worker counts, completion gate, and unread worker handoffs.",
      inputSchema: z.object({
        includeInbox: z.boolean().optional().default(true),
        limit: z.number().int().min(1).max(100).default(25),
        offset: z.number().int().min(0).default(0),
        toolCallDescription: z.string(),
      }),
      execute: async ({ includeInbox, limit, offset }) => {
        const state = store.snapshot();
        const objectives = state.objectives.slice(offset, offset + limit);
        const objectiveIds = new Set(objectives.map((item) => item.id));
        const workerCounts = state.workers.reduce(
          (counts, worker) => {
            counts[worker.status] += 1;
            return counts;
          },
          { queued: 0, running: 0, completed: 0, failed: 0 },
        );
        return {
          success: true,
          state: {
            version: state.version,
            rootTarget: state.rootTarget,
            services: state.services.slice(offset, offset + limit),
            objectives,
            coverage: state.coverage.filter((item) =>
              objectiveIds.has(item.objectiveId),
            ),
            capabilities: state.capabilities.slice(offset, offset + limit),
            impactProofs: state.impactProofs.slice(offset, offset + limit),
            missions: state.missions
              ? {
                  planningStatus: state.missions.planningStatus,
                  missions: state.missions.missions.slice(
                    offset,
                    offset + limit,
                  ),
                }
              : undefined,
            workerCounts,
            chainExplore: state.chainExplore,
            updatedAt: state.updatedAt,
          },
          pagination: {
            offset,
            limit,
            serviceTotal: state.services.length,
            objectiveTotal: state.objectives.length,
            workerTotal: state.workers.length,
          },
          completion: boundedCompletion(),
          inbox: includeInbox ? mailbox.take(leadAgentId) : [],
        };
      },
    }),

    spawn_engagement_worker: tool({
      description:
        "Delegate focused exploration or chain work after planning. Grouped baseline missions are launched only by the scheduler.",
      inputSchema: WorkerAssignmentSchema,
      execute: async (assignment) => {
        if (
          input.session.config?.engagementCoverageMode === "grouped" &&
          store.snapshot().missions?.planningStatus !== "complete"
        )
          throw new Error("Seal the mission plan before delegating workers");
        if (assignment.mode === "grouped")
          throw new Error(
            "Grouped missions are launched only from the sealed plan",
          );
        return dispatchWorker(assignment);
      },
    }),

    send_engagement_worker_message: tool({
      description:
        "Send a durable directed message to a running grouped worker. It is injected at the next model-step boundary.",
      inputSchema: z.object({
        workerId: z.string().min(1),
        message: z.string().min(1),
        toolCallDescription: z.string(),
      }),
      execute: async ({ workerId, message }) => {
        const worker = store
          .snapshot()
          .workers.find((candidate) => candidate.id === workerId);
        if (!worker) throw new Error(`Unknown engagement worker: ${workerId}`);
        if (worker.status !== "running") {
          throw new Error(`Worker ${workerId} is not running`);
        }
        const delivered = mailbox.send({
          type: "MESSAGE",
          recipientAgentId: workerId,
          senderAgentId: leadAgentId,
          taskName: worker.mission,
          payload: message,
        });
        return withCheckpoint({ success: true, messageId: delivered.id });
      },
    }),

    wait_for_engagement_workers: tool({
      description:
        "Wait briefly for grouped worker progress, then return bounded worker status and unread handoffs.",
      inputSchema: z.object({
        workerIds: z.array(z.string()).max(100).default([]),
        timeoutMs: z.number().int().min(100).max(10_000).default(2_000),
        toolCallDescription: z.string(),
      }),
      execute: async ({ workerIds, timeoutMs }) => {
        const selected =
          workerIds.length > 0
            ? workerIds
            : [...workerJobs.keys()].slice(0, 100);
        const jobs = selected
          .map((id) => workerJobs.get(id))
          .filter((job): job is Promise<Record<string, unknown>> =>
            Boolean(job),
          );
        if (jobs.length > 0) {
          await Promise.race([
            Promise.race(jobs).catch(() => undefined),
            new Promise((resolve) => setTimeout(resolve, timeoutMs)),
          ]);
        }
        const selectedIds = new Set(selected);
        return {
          success: true,
          workers: store
            .snapshot()
            .workers.filter((worker) => selectedIds.has(worker.id))
            .slice(0, 100),
          inbox: mailbox.take(leadAgentId, 100),
        };
      },
    }),

    follow_up_engagement_worker: tool({
      description:
        "Resume a completed durable worker with its preserved conversation and a directed follow-up. Use this for stateful chains instead of spawning a fresh worker.",
      inputSchema: z.object({
        workerId: z.string().min(1),
        message: z.string().min(1),
        toolCallDescription: z.string(),
      }),
      execute: async ({ workerId, message }) => {
        const worker = store
          .snapshot()
          .workers.find((candidate) => candidate.id === workerId);
        if (!worker) throw new Error(`Unknown engagement worker: ${workerId}`);
        if (worker.status === "running") {
          throw new Error(`Worker ${workerId} is still running`);
        }
        mailbox.send({
          type: "MESSAGE",
          recipientAgentId: workerId,
          senderAgentId: leadAgentId,
          taskName: worker.mission,
          payload: message,
        });
        const messages = loadSubagentMessages(input.session, workerId);
        messages.push({
          role: "user",
          content: [{ type: "text", text: message }],
        });
        const mission = store
          .snapshot()
          .missions?.missions.find(
            (candidate) => candidate.workerId === workerId,
          );
        return workerPool.run("chain", () =>
          runWorker({
            workerId,
            mission: worker.mission,
            mode: worker.mode,
            serviceIds: worker.serviceIds,
            targetIds: worker.targetIds,
            objectiveIds: worker.objectiveIds,
            capabilityIds: worker.capabilityIds,
            missionId: mission?.id,
            coverage: mission?.coverage,
            messages,
            followUp: true,
          }),
        );
      },
    }),

    update_engagement_coverage: tool({
      description:
        "Update the single-writer coverage ledger after direct lead testing or after reviewing worker evidence. Use objective, service, or chain kind and provide the matching status and IDs.",
      inputSchema: z.object({
        kind: z.enum(["objective", "service", "chain"]),
        targetId: z.string().optional(),
        objectiveId: z.string().optional(),
        serviceId: z.string().optional(),
        objectiveStatus: z.enum(COVERAGE_STATUSES).optional(),
        serviceStatus: z.enum(SERVICE_STATUSES).optional(),
        chainStatus: z.enum(CHAIN_STATUSES).optional(),
        summary: z.string().min(1),
        evidence: z.array(z.string()).optional().default([]),
        toolCallDescription: z.string(),
      }),
      execute: async (update) => {
        if (update.kind === "objective") {
          if (
            !update.targetId ||
            !update.objectiveId ||
            !update.serviceId ||
            !update.objectiveStatus
          ) {
            throw new Error(
              "Objective coverage requires targetId, objectiveId, serviceId, and objectiveStatus",
            );
          }
          return withCheckpoint({
            success: true,
            coverage: store.markObjectiveCoverage({
              targetId: update.targetId,
              objectiveId: update.objectiveId,
              serviceId: update.serviceId,
              status: update.objectiveStatus,
              summary: update.summary,
              evidence: update.evidence,
            }),
            completion: store.completion(),
          });
        }
        if (update.kind === "service") {
          if (!update.serviceId || !update.serviceStatus) {
            throw new Error(
              "Service coverage requires serviceId and serviceStatus",
            );
          }
          return withCheckpoint({
            success: true,
            service: store.markServiceBaseline(
              update.serviceId,
              update.serviceStatus,
              update.summary,
            ),
            completion: store.completion(),
          });
        }
        if (!update.chainStatus) {
          throw new Error("Chain coverage requires chainStatus");
        }
        return withCheckpoint({
          success: true,
          chainExplore: store.setChainExplore(
            update.chainStatus,
            update.summary,
            update.evidence,
          ),
          completion: store.completion(),
        });
      },
    }),

    record_engagement_capability: tool({
      description:
        "Create or update a reusable exploit primitive. Candidate or confirmed capabilities with open nextSteps prevent engagement completion until consumed or blocked.",
      inputSchema: z.object({
        id: z.string().optional(),
        label: z.string().min(1),
        description: z.string().min(1),
        status: z.enum(["candidate", "confirmed", "consumed", "blocked"]),
        serviceIds: z.array(z.string()).default([]),
        targetIds: z.array(z.string()).default([]),
        objectiveIds: z.array(z.string()).default([]),
        evidence: z.array(z.string()).default([]),
        nextSteps: z.array(z.string()).default([]),
        toolCallDescription: z.string(),
      }),
      execute: async (capability) =>
        withCheckpoint({
          success: true,
          capability: store.upsertCapability(capability),
          completion: store.completion(),
        }),
    }),

    record_impact_proof: tool({
      description:
        "Record material impact using references to accepted findings, capabilities, artifacts, and trace observations. This does not replace document_vulnerability or its finding judge.",
      inputSchema: z.object({
        description: z.string().min(1),
        objectiveIds: z.array(z.string()).default([]),
        serviceIds: z.array(z.string()).default([]),
        targetIds: z.array(z.string()).default([]),
        findingIds: z.array(z.string()).default([]),
        capabilityIds: z.array(z.string()).default([]),
        artifactPaths: z.array(z.string()).default([]),
        observationRefs: z.array(z.string()).default([]),
        toolCallDescription: z.string(),
      }),
      execute: async (proof) =>
        withCheckpoint({
          success: true,
          proof: store.addImpactProof(proof),
        }),
    }),
  };
  const startPlannedMissions = async (): Promise<void> => {
    const state = store.snapshot();
    if (state.missions?.planningStatus !== "complete")
      throw new Error("Cannot execute an unsealed mission plan");
    const jobs = new Map<string, Promise<Record<string, unknown>>>();
    const schedule = (
      mission: EngagementMission,
    ): Promise<Record<string, unknown>> => {
      const existing = jobs.get(mission.id);
      if (existing) return existing;
      const prerequisites = mission.prerequisiteMissionIds.map((id) => {
        const dependency = state.missions?.missions.find(
          (candidate) => candidate.id === id,
        );
        if (!dependency) throw new Error(`Unknown prerequisite mission: ${id}`);
        return schedule(dependency);
      });
      const job = Promise.all(prerequisites).then(async () => {
        if (mission.status === "completed") return { success: true };
        if (mission.status === "failed") return { success: false };
        if (input.abortSignal?.aborted) throw input.abortSignal.reason;
        const failed = mission.prerequisiteMissionIds.some(
          (id) =>
            store.snapshot().missions?.missions.find((item) => item.id === id)
              ?.status !== "completed",
        );
        if (failed) {
          store.setMissionStatus(mission.id, "failed");
          for (const cell of mission.coverage)
            store.markObjectiveCoverage({
              ...cell,
              serviceId: store.getTarget(cell.targetId).serviceId,
              status: "needs-lead",
              summary: "Prerequisite mission did not complete",
            });
          return withCheckpoint({ success: false, missionId: mission.id });
        }
        const coverage = mission.coverage.filter((cell) =>
          store
            .snapshot()
            .coverage.some(
              (item) =>
                item.targetId === cell.targetId &&
                item.objectiveId === cell.objectiveId &&
                (item.status === "pending" || item.status === "assigned"),
            ),
        );
        if (!coverage.length) {
          store.setMissionStatus(mission.id, "completed");
          return withCheckpoint({ success: true, missionId: mission.id });
        }
        const targetIds = unique([
          ...coverage.map((cell) => cell.targetId),
          ...mission.supportingTargetIds,
          ...mission.contextTargetIds,
        ]);
        await dispatchWorker(
          {
            mission: mission.purpose,
            rationale: mission.rationale,
            coverage,
            serviceIds: unique(
              targetIds.map((id) => store.getTarget(id).serviceId),
            ),
            targetIds,
            objectiveIds: unique(coverage.map((cell) => cell.objectiveId)),
            capabilityIds: [],
            supportingTargetIds: mission.supportingTargetIds,
            contextTargetIds: mission.contextTargetIds,
            prerequisiteMissionIds: [],
            mode: "grouped",
            toolCallDescription: "Run sealed mission",
          },
          mission,
        );
        const workerJob = workerJobs.get(mission.workerId);
        if (!workerJob) {
          throw new Error(`Mission ${mission.id} did not create a worker job`);
        }
        return workerJob;
      });
      jobs.set(mission.id, job);
      return job;
    };
    await Promise.all(state.missions.missions.map(schedule));
  };
  const takeLeadHandoffs = () => mailbox.take(leadAgentId, 100);
  const waitForWorkerActivity = async () => {
    const jobs = [...workerJobs.values()];
    if (jobs.length === 0) return;
    await Promise.race(jobs.map((job) => job.catch(() => undefined)));
  };
  return {
    tools,
    startPlannedMissions,
    takeLeadHandoffs,
    waitForWorkerActivity,
    hasActiveWorkers: () => workerJobs.size > 0,
  };
}
