import type { ModelMessage, ToolSet } from "ai";
import { tool } from "ai";
import { z } from "zod";
import { TargetedPentestAgent } from "../agents/specialized/pentest/agent";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import { newSessionId } from "../id/id";
import { loadSubagentMessages, saveSubagentData } from "../session/persistence";
import {
  AgentMailbox,
  type EngagementStore,
  type EngagementWorkerMode,
} from "./engagementState";
import { runFastStrikeObjective } from "./fastStrike";
import type { PentestWorkflowInput } from "./pentest";

const COVERAGE_STATUSES = [
  "pending",
  "running",
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
const WORKER_MODES = ["targeted", "fast-strike", "explore"] as const;

export const ENGAGEMENT_TOOL_NAMES = [
  "read_engagement_state",
  "spawn_engagement_worker",
  "follow_up_engagement_worker",
  "update_engagement_coverage",
  "record_engagement_capability",
  "record_impact_proof",
] as const;

interface EngagementToolRuntime {
  input: PentestWorkflowInput;
  store: EngagementStore;
  findingsRegistry: FindingsRegistry;
  eventBus: AgentEventBus;
  leadAgentId: string;
  surfaceTools?: ToolSet;
  engagementTargetIds?: string[];
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function buildWorkerContext(
  store: EngagementStore,
  mission: string,
  serviceIds: string[],
  objectiveIds: string[],
): string {
  const state = store.snapshot();
  const services = serviceIds.map((id) => store.getService(id));
  const objectives = objectiveIds.map((id) => store.getObjective(id));
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
    objectives.length > 0
      ? `Assigned objective IDs:\n${objectives
          .map((objective) => `- ${objective.id}: ${objective.text}`)
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
  objectiveIds: string[],
): void {
  if (serviceIds.length === 0)
    throw new Error("At least one serviceId is required");
  for (const serviceId of serviceIds) store.getService(serviceId);
  for (const objectiveId of objectiveIds) {
    const objective = store.getObjective(objectiveId);
    if (!objective.relevantServiceIds.some((id) => serviceIds.includes(id))) {
      throw new Error(
        `Objective ${objectiveId} is not relevant to the selected services`,
      );
    }
  }
  if (
    mode === "fast-strike" &&
    (serviceIds.length !== 1 || objectiveIds.length !== 1)
  ) {
    throw new Error(
      "Fast Strike workers require exactly one service and objective",
    );
  }
  if (mode === "targeted" && objectiveIds.length === 0) {
    throw new Error("Targeted workers require at least one objectiveId");
  }
}

export function createEngagementTools(runtime: EngagementToolRuntime) {
  const {
    input,
    store,
    findingsRegistry,
    eventBus,
    leadAgentId,
    surfaceTools,
    engagementTargetIds = [],
  } = runtime;
  const mailbox = new AgentMailbox(input.session.rootPath);
  const activeWorkers = new Set<string>();
  const withCheckpoint = <T extends Record<string, unknown>>(result: T) => ({
    checkpoint: store.checkpoint(),
    ...result,
  });

  const runWorker = async (options: {
    workerId: string;
    mission: string;
    mode: EngagementWorkerMode;
    serviceIds: string[];
    objectiveIds: string[];
    messages?: ModelMessage[];
    followUp?: boolean;
  }) => {
    if (activeWorkers.has(options.workerId)) {
      throw new Error(`Worker ${options.workerId} is already running`);
    }
    activeWorkers.add(options.workerId);
    if (options.followUp) {
      store.restartWorker(options.workerId);
      if (options.mode === "explore") {
        for (const serviceId of options.serviceIds) {
          store.markServiceBaseline(serviceId, "running", options.mission);
        }
      } else {
        for (const objectiveId of options.objectiveIds) {
          const objective = store.getObjective(objectiveId);
          for (const serviceId of objective.relevantServiceIds.filter((id) =>
            options.serviceIds.includes(id),
          )) {
            store.markObjectiveCoverage({
              objectiveId,
              serviceId,
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
    const target = services[0]?.targets[0] ?? input.target;
    const context = buildWorkerContext(
      store,
      options.mission,
      options.serviceIds,
      options.objectiveIds,
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
        objectiveIds: options.objectiveIds,
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
          ...input,
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
          objectiveId: objective.id,
          serviceId: services[0]?.id as string,
          status: outcome.status,
          workerId: options.workerId,
          summary,
          evidence: (outcome.evidence ?? []).map(
            (reference) => `${reference.toolName}:${reference.toolCallId}`,
          ),
        });
      } else {
        const agent = new TargetedPentestAgent({
          target,
          objectives:
            objectives.length > 0
              ? objectives.map((objective) => objective.text)
              : [options.mission],
          context,
          model: input.model,
          session: input.session,
          authConfig: input.authConfig,
          abortSignal: input.abortSignal,
          findingsRegistry,
          eventBus: childBus,
          subagentId: options.workerId,
          subagentName: options.mission.slice(0, 80),
          messages: options.messages,
          onStepFinish: handleStepFinish,
          enableThinking: input.enableThinking,
          thinkingEffort: input.thinkingEffort,
          openAIReasoningEffort: input.openAIReasoningEffort,
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
        } else {
          for (const objective of objectives) {
            const objectiveResult = outcome.objectiveResults?.find(
              (candidate) => candidate.objective === objective.text,
            );
            for (const serviceId of objective.relevantServiceIds.filter((id) =>
              options.serviceIds.includes(id),
            )) {
              store.markObjectiveCoverage({
                objectiveId: objective.id,
                serviceId,
                status: objectiveResult?.completed ? "exhausted" : "blocked",
                workerId: options.workerId,
                summary: objectiveResult?.result ?? summary,
              });
            }
          }
        }
      }

      store.completeWorker(options.workerId, "completed", summary);
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
      store.completeWorker(options.workerId, "failed", summary);
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
        "Read a page of the persisted engagement services, objectives, and coverage plus capabilities, impact proofs, worker records, completion gate, and unread worker handoffs.",
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
        return {
          success: true,
          state: {
            ...state,
            services: state.services.slice(offset, offset + limit),
            objectives,
            coverage: state.coverage.filter((item) =>
              objectiveIds.has(item.objectiveId),
            ),
          },
          pagination: {
            offset,
            limit,
            serviceTotal: state.services.length,
            objectiveTotal: state.objectives.length,
          },
          completion: store.completion(),
          inbox: includeInbox ? mailbox.take(leadAgentId) : [],
        };
      },
    }),

    spawn_engagement_worker: tool({
      description:
        "Start a durable focused worker. Use targeted for assigned objective coverage, fast-strike for one concrete impact goal, and explore for baseline service discovery or net-new vulnerability paths. Independent calls may run in parallel.",
      inputSchema: z.object({
        mission: z.string().min(1),
        serviceIds: z.array(z.string()).min(1),
        objectiveIds: z.array(z.string()).default([]),
        mode: z.enum(WORKER_MODES),
        toolCallDescription: z.string(),
      }),
      execute: async ({ mission, serviceIds, objectiveIds, mode }) => {
        const selectedServiceIds = unique(serviceIds);
        const selectedObjectiveIds = unique(objectiveIds);
        validateAssignment(
          store,
          mode,
          selectedServiceIds,
          selectedObjectiveIds,
        );
        const workerId = newSessionId() as string;
        store.registerWorker({
          id: workerId,
          mission,
          mode,
          serviceIds: selectedServiceIds,
          objectiveIds: selectedObjectiveIds,
        });
        if (mode === "explore") {
          for (const serviceId of selectedServiceIds) {
            store.markServiceBaseline(serviceId, "running", mission);
          }
        } else {
          for (const objectiveId of selectedObjectiveIds) {
            const objective = store.getObjective(objectiveId);
            for (const serviceId of objective.relevantServiceIds.filter((id) =>
              selectedServiceIds.includes(id),
            )) {
              store.markObjectiveCoverage({
                objectiveId,
                serviceId,
                status: "running",
                workerId,
                summary: mission,
              });
            }
          }
        }
        return runWorker({
          workerId,
          mission,
          mode,
          serviceIds: selectedServiceIds,
          objectiveIds: selectedObjectiveIds,
        });
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
        return runWorker({
          workerId,
          mission: worker.mission,
          mode: worker.mode,
          serviceIds: worker.serviceIds,
          objectiveIds: worker.objectiveIds,
          messages,
          followUp: true,
        });
      },
    }),

    update_engagement_coverage: tool({
      description:
        "Update the single-writer coverage ledger after direct lead testing or after reviewing worker evidence. Use objective, service, or chain kind and provide the matching status and IDs.",
      inputSchema: z.object({
        kind: z.enum(["objective", "service", "chain"]),
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
            !update.objectiveId ||
            !update.serviceId ||
            !update.objectiveStatus
          ) {
            throw new Error(
              "Objective coverage requires objectiveId, serviceId, and objectiveStatus",
            );
          }
          return withCheckpoint({
            success: true,
            coverage: store.markObjectiveCoverage({
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
