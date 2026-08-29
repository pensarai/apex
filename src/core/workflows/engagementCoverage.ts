import type { ModelMessage, ToolSet } from "ai";
import { TargetedPentestAgent } from "../agents/specialized/pentest/agent";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import { newSessionId } from "../id/id";
import { saveSubagentData } from "../session/persistence";
import {
  AgentMailbox,
  type EngagementCheckpoint,
  type EngagementState,
  type EngagementStore,
  engagementCoverageCellId,
  type ObjectiveCoverage,
} from "./engagementState";
import type { EngagementWorkerPool } from "./engagementWorkerPool";
import type { PentestWorkflowInput } from "./pentest";

export const ENGAGEMENT_COVERAGE_BATCH_SIZE = 6;

export interface EngagementCoverageBatch {
  serviceId: string;
  objectiveId: string;
  cells: Array<Pick<ObjectiveCoverage, "targetId" | "objectiveId">>;
  retry: boolean;
}

export function buildEngagementCoverageBatches(
  state: EngagementState,
  batchSize = ENGAGEMENT_COVERAGE_BATCH_SIZE,
): EngagementCoverageBatch[] {
  const pending = state.coverage
    .filter((cell) => cell.status === "pending")
    .sort((left, right) =>
      engagementCoverageCellId(left.targetId, left.objectiveId).localeCompare(
        engagementCoverageCellId(right.targetId, right.objectiveId),
      ),
    );
  const retries = pending
    .filter((cell) => cell.attempts > 0)
    .map((cell) => ({
      serviceId: cell.serviceId,
      objectiveId: cell.objectiveId,
      cells: [{ targetId: cell.targetId, objectiveId: cell.objectiveId }],
      retry: true,
    }));
  const groups = new Map<string, ObjectiveCoverage[]>();
  for (const cell of pending.filter((candidate) => candidate.attempts === 0)) {
    const key = `${cell.serviceId}:${cell.objectiveId}`;
    const group = groups.get(key) ?? [];
    group.push(cell);
    groups.set(key, group);
  }
  const initial: EngagementCoverageBatch[] = [];
  for (const group of groups.values()) {
    for (let offset = 0; offset < group.length; offset += batchSize) {
      const cells = group.slice(offset, offset + batchSize);
      const first = cells[0];
      if (!first) continue;
      initial.push({
        serviceId: first.serviceId,
        objectiveId: first.objectiveId,
        cells: cells.map(({ targetId, objectiveId }) => ({
          targetId,
          objectiveId,
        })),
        retry: false,
      });
    }
  }
  return [...retries, ...initial];
}

function assignmentText(input: {
  targetId: string;
  target: string;
  objectiveId: string;
  objective: string;
}): string {
  return `[${input.targetId}:${input.objectiveId}] Test ${input.target} — ${input.objective}`;
}

export async function runDeterministicEngagementCoverage(input: {
  workflow: PentestWorkflowInput;
  store: EngagementStore;
  pool: EngagementWorkerPool;
  findingsRegistry: FindingsRegistry;
  eventBus: AgentEventBus;
  leadAgentId: string;
  surfaceTools?: ToolSet;
  engagementTargetIds: string[];
  onCheckpoint?: (checkpoint: EngagementCheckpoint) => void | Promise<void>;
}): Promise<void> {
  const mailbox = new AgentMailbox(input.workflow.session.rootPath);

  const runBatch = async (batch: EngagementCoverageBatch): Promise<void> => {
    const workerId = newSessionId() as string;
    const claimed = input.store.claimCoverageCells({
      workerId,
      cells: batch.cells,
    });
    if (claimed.length === 0) return;
    const targetIds = claimed.map((cell) => cell.targetId);
    const targets = targetIds.map((targetId) =>
      input.store.getTarget(targetId),
    );
    const objective = input.store.getObjective(batch.objectiveId);
    const assignments = targets.map((target) =>
      assignmentText({
        targetId: target.id,
        target: target.target,
        objectiveId: objective.id,
        objective: objective.text,
      }),
    );
    const mission = batch.retry
      ? `Retry unresolved coverage for ${objective.text}`
      : `Cover ${objective.text} across ${targets.length} related target(s)`;
    input.store.registerWorker({
      id: workerId,
      mission,
      mode: "targeted",
      serviceIds: [batch.serviceId],
      targetIds,
      objectiveIds: [batch.objectiveId],
      capabilityIds: [],
    });
    const childBus = new AgentEventBus();
    AgentEventBus.attachChild(childBus, input.eventBus, workerId);
    input.eventBus.emit("subagent-spawn", {
      subagentId: workerId,
      sessionId: workerId,
      name: mission,
      input: { mission, targetIds, objectiveIds: [batch.objectiveId] },
      parentSubagentId: input.leadAgentId,
      parentSessionId: input.leadAgentId,
    });
    let latestMessages: ModelMessage[] = [];
    let summary = "Coverage worker did not return a result.";
    let workerStatus: "completed" | "failed" = "completed";
    try {
      const agent = new TargetedPentestAgent({
        target: targets[0]?.target ?? input.workflow.target,
        objectives: assignments,
        context: [
          "This is a deterministic coverage batch. Test every assigned target and return one objectiveResult for every assignment verbatim.",
          "Perform bounded baseline reconnaissance on each target while testing the stated objective. Do not declare the whole engagement complete.",
          "Use get_engagement_target for immutable threat-model and business-logic context. Preserve reusable cross-target primitives in your summary for the engagement lead.",
        ].join("\n\n"),
        model: input.workflow.model,
        session: input.workflow.session,
        authConfig: input.workflow.authConfig,
        abortSignal: input.workflow.abortSignal,
        findingsRegistry: input.findingsRegistry,
        eventBus: childBus,
        subagentId: workerId,
        subagentName: mission,
        onStepFinish: (event) => {
          if (event.response.messages) latestMessages = event.response.messages;
          input.workflow.onStepFinish?.(event);
        },
        enableThinking: input.workflow.enableThinking,
        thinkingEffort: input.workflow.thinkingEffort,
        openAIReasoningEffort: input.workflow.openAIReasoningEffort,
        environmentVariables: input.workflow.environmentVariables,
        secretValues: input.workflow.secretValues,
        sandbox: input.workflow.sandbox,
        display: input.workflow.display,
        role: "worker",
        toolProtocol: input.workflow.toolProtocol,
        extraTools: input.surfaceTools,
        directTools: input.surfaceTools
          ? Object.keys(input.surfaceTools)
          : undefined,
        engagementTargetIds: input.engagementTargetIds,
      });
      const outcome = await agent.consume();
      const summaries: string[] = [];
      for (const cell of claimed) {
        const target = input.store.getTarget(cell.targetId);
        const assignment = assignmentText({
          targetId: target.id,
          target: target.target,
          objectiveId: objective.id,
          objective: objective.text,
        });
        const result = outcome.objectiveResults?.find(
          (candidate) => candidate.objective === assignment,
        );
        const nextAttempt = cell.attempts + 1;
        const status = result?.completed
          ? "exhausted"
          : nextAttempt >= 2
            ? "needs-lead"
            : "pending";
        const resultSummary =
          result?.result ??
          (result
            ? "Coverage worker returned an incomplete result."
            : "Coverage worker omitted this assigned target.");
        input.store.settleCoverageCell({
          targetId: cell.targetId,
          objectiveId: cell.objectiveId,
          workerId,
          status,
          summary: resultSummary,
        });
        summaries.push(`${cell.targetId}: ${resultSummary}`);
      }
      summary = summaries.join("\n");
      input.store.completeWorker(workerId, "completed", summary);
    } catch (error) {
      workerStatus = "failed";
      summary = error instanceof Error ? error.message : String(error);
      const interrupted = input.workflow.abortSignal?.aborted === true;
      for (const cell of claimed) {
        input.store.settleCoverageCell({
          targetId: cell.targetId,
          objectiveId: cell.objectiveId,
          workerId,
          status: interrupted
            ? "pending"
            : cell.attempts + 1 >= 2
              ? "needs-lead"
              : "pending",
          summary,
          attempted: !interrupted,
        });
      }
      input.store.completeWorker(workerId, "failed", summary);
    }
    mailbox.send({
      type: "FINAL_ANSWER",
      recipientAgentId: input.leadAgentId,
      senderAgentId: workerId,
      taskName: mission,
      payload: summary,
      status: workerStatus,
    });
    saveSubagentData(input.workflow.session, {
      agentName: workerId,
      target: targets[0]?.target ?? input.workflow.target,
      objective: mission,
      status: workerStatus,
      messages: latestMessages,
      findingsCount: input.findingsRegistry.getFindings().length,
    });
    input.eventBus.emit("subagent-complete", {
      subagentId: workerId,
      sessionId: workerId,
      status: workerStatus,
      parentSubagentId: input.leadAgentId,
      parentSessionId: input.leadAgentId,
    });
    await input.onCheckpoint?.(input.store.checkpoint());
  };

  while (!input.workflow.abortSignal?.aborted) {
    const batches = buildEngagementCoverageBatches(input.store.snapshot());
    if (batches.length === 0) return;
    const settled = await Promise.allSettled(
      batches.map((batch) =>
        input.pool.run(batch.retry ? "retry" : "baseline", () =>
          runBatch(batch),
        ),
      ),
    );
    const failure = settled.find(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    if (failure) throw failure.reason;
  }
}
