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
  type EngagementMissionCoverage,
  type EngagementModelConfig,
  GROUPED_MISSION_SYSTEM_PROMPT,
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
  "complete_engagement_mission_plan",
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
    if (options.missionId) store.setMissionStatus(options.missionId, "running");
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
    const objectives = options.objectiveIds.map((id) => store.getObjective(id));
    const targets = options.targetIds.map((id) => store.getTarget(id));
    const workerWorkflow =
      options.mode === "chain"
        ? input
        : applyEngagementModel(input, workerModel);
    const target =
      targets[0]?.target ?? services[0]?.targets[0] ?? input.target;
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

    let latestMessages: ModelMessage[] = [];
    const handleStepFinish = (
      event: Parameters<NonNullable<PentestWorkflowInput["onStepFinish"]>>[0],
    ) => {
      if (event.response.messages) latestMessages = event.response.messages;
      input.onStepFinish?.(event);
    };
    try {
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
            activeTools: [],
            extraTools: surfaceTools,
            directTools: surfaceTools ? Object.keys(surfaceTools) : undefined,
            engagementTargetIds,
            responseSchema: GroupedMissionResult,
            responseGuard: (candidate) => {
              const parsed = GroupedMissionResult.safeParse(candidate);
              if (!parsed.success)
                return "Return one valid result per coverage obligation.";
              const expected = new Set(
                assigned.map((cell) => `${cell.targetId}:${cell.objectiveId}`),
              );
              const returned = parsed.data.obligationResults.map(
                (cell) => `${cell.targetId}:${cell.objectiveId}`,
              );
              if (
                returned.length !== expected.size ||
                new Set(returned).size !== returned.length ||
                returned.some((cell) => !expected.has(cell))
              ) {
                return "Results must match the assigned target/objective obligations exactly once.";
              }
              for (const obligation of parsed.data.obligationResults) {
                if (obligation.status !== "impact-proven") continue;
                const rejection = evidenceLedger.validateImpactEvidence(
                  obligation.evidence,
                  new Set([options.workerId]),
                );
                if (rejection) return rejection;
              }
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
          for (const obligation of outcome.obligationResults) {
            const settled = store.settleCoverageCell({
              targetId: obligation.targetId,
              objectiveId: obligation.objectiveId,
              workerId: options.workerId,
              status: obligation.status,
              summary: obligation.summary,
              evidence: obligation.evidence.map(
                (reference) => `${reference.toolName}:${reference.toolCallId}`,
              ),
            });
            if (!settled && !options.followUp) {
              throw new Error(
                `Worker no longer owns coverage ${obligation.targetId}:${obligation.objectiveId}`,
              );
            }
          }
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
      const summary = error instanceof Error ? error.message : String(error);
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

  return {
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
          { running: 0, completed: 0, failed: 0 },
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
        "Start a durable focused worker. In grouped coverage mode, use grouped with explicit target/objective obligations plus rationale and context; use chain for cross-mission exploitation. Legacy modes also support targeted, fast-strike, and explore. Grouped calls return immediately and independent missions run concurrently.",
      inputSchema: z.object({
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
      }),
      execute: async ({
        mission,
        serviceIds,
        targetIds,
        objectiveIds,
        capabilityIds,
        rationale,
        coverage,
        supportingTargetIds,
        prerequisiteMissionIds,
        contextTargetIds,
        mode,
      }) => {
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
          throw new Error(
            "Grouped workers require grouped engagement coverage",
          );
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
            selectedCoverage.map(
              (cell) => `${cell.targetId}:${cell.objectiveId}`,
            ),
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
            if (coverageCell?.status !== "pending") {
              throw new Error(
                `Coverage ${cell.targetId}:${cell.objectiveId} is already assigned or terminal`,
              );
            }
          }
        }
        const workerId = newSessionId() as string;
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
        const missionId =
          mode === "grouped" ? `mission_${workerId}` : undefined;
        if (missionId) {
          const existingMissionIds = new Set(
            store.snapshot().missions?.missions.map((mission) => mission.id) ??
              [],
          );
          for (const prerequisite of prerequisiteMissionIds ?? []) {
            if (!existingMissionIds.has(prerequisite)) {
              throw new Error(`Unknown prerequisite mission: ${prerequisite}`);
            }
          }
          store.addMission({
            id: missionId,
            workerId,
            purpose: mission,
            rationale: rationale as string,
            coverage: selectedCoverage,
            supportingTargetIds: unique(supportingTargetIds ?? []),
            prerequisiteMissionIds: unique(prerequisiteMissionIds ?? []),
            contextTargetIds: unique(contextTargetIds ?? []),
            status: "queued",
            createdAt: new Date().toISOString(),
          });
        }
        if (mode === "explore") {
          for (const serviceId of selectedServiceIds) {
            store.markServiceBaseline(serviceId, "running", mission);
          }
        } else if (mode === "grouped") {
          const claimed = store.claimCoverageCells({
            workerId,
            cells: selectedCoverage,
          });
          if (claimed.length !== selectedCoverage.length) {
            throw new Error(
              "One or more grouped coverage obligations are already assigned or terminal",
            );
          }
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
            }),
          );
        const prerequisites = (prerequisiteMissionIds ?? [])
          .map((id) => {
            const mission = store
              .snapshot()
              .missions?.missions.find((candidate) => candidate.id === id);
            return mission ? workerJobs.get(mission.workerId) : undefined;
          })
          .filter((job): job is Promise<Record<string, unknown>> =>
            Boolean(job),
          );
        const job =
          mode === "grouped" && prerequisites.length > 0
            ? Promise.all(prerequisites).then(() => {
                for (const prerequisiteId of prerequisiteMissionIds ?? []) {
                  const prerequisite = store
                    .snapshot()
                    .missions?.missions.find(
                      (candidate) => candidate.id === prerequisiteId,
                    );
                  if (prerequisite?.status !== "completed") {
                    throw new Error(
                      `Prerequisite mission ${prerequisiteId} did not complete`,
                    );
                  }
                }
                return run();
              })
            : run();
        if (mode !== "grouped") return job;
        const resilientJob = job.catch(async (error) => {
          const summary =
            error instanceof Error ? error.message : String(error);
          const worker = store
            .snapshot()
            .workers.find((candidate) => candidate.id === workerId);
          if (worker?.status === "running") {
            for (const cell of store.snapshot().coverage) {
              if (cell.workerId !== workerId || cell.status !== "running")
                continue;
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
      },
    }),

    complete_engagement_mission_plan: tool({
      description:
        "Seal the model-created grouped mission plan. Fails unless every required endpoint/objective obligation appears in exactly one accepted mission.",
      inputSchema: z.object({ toolCallDescription: z.string() }),
      execute: async () =>
        withCheckpoint({
          success: true,
          missions: store.setMissionPlanningComplete(),
        }),
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
}
