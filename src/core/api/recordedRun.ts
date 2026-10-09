import { stat } from "node:fs/promises";
import {
  type AIAuthConfig,
  AVAILABLE_MODELS,
  runWithInferenceRecorder,
} from "../ai";
import type { CredentialManager } from "../credentials";
import type { AgentEventBus } from "../eventBus";
import { createRunContextRecorder } from "../runtime/runContext";
import { runDeadline } from "../runtime/runDeadline";
import { collectSessionEvidence } from "../runtime/runEvidence";
import { createRunInferenceRecorder } from "../runtime/runInference";
import type { RunModelStore } from "../runtime/runModelStore";
import { RecordedRunSpecSchema, type RunRecord } from "../runtime/runStore";
import { create as createSession } from "../session";
import { type RunAgentResult, runOffensiveSecurityAgent } from "./offesecAgent";

const TASK_TOOL_NAMES = new Set(["create_task", "update_task", "list_tasks"]);

export type RecordedRunAgentInput = {
  /** Raw (unparsed) run spec — the parsed, normalized form is the only version stored or executed. */
  spec: unknown;
  store: RunModelStore;
  authConfig?: AIAuthConfig;
  credentialManager?: CredentialManager;
  eventBus?: AgentEventBus;
  abortSignal?: AbortSignal;
};

export type RecordedRunOutcome = {
  /** Whether this invocation called the agent. */
  started: boolean;
  record: RunRecord;
  /** Present when the agent returned, including a cancelled stream. */
  result?: RunAgentResult;
};

// The runtime manager must resolve exactly the admitted credential references.
function assertCredentialsDeclared(
  spec: { credentialRefs: string[] },
  manager: CredentialManager | undefined,
): void {
  for (const credentialId of spec.credentialRefs) {
    if (!manager?.getReference(credentialId)) {
      throw new Error(
        `Referenced credential is not available: ${credentialId}`,
      );
    }
  }
  const declared = new Set(spec.credentialRefs);
  for (const reference of manager?.listReferences() ?? []) {
    if (!declared.has(reference.id)) {
      throw new Error(
        `Credential manager holds an undeclared credential: ${reference.id}`,
      );
    }
  }
}

/** Commit admission before execution; duplicate IDs only return saved status. */
export async function runRecordedAgent(
  input: RecordedRunAgentInput,
): Promise<RecordedRunOutcome> {
  const spec = RecordedRunSpecSchema.parse(input.spec);
  const admission = await input.store.admit(spec);
  if (!admission.created) {
    return { started: false, record: admission.record };
  }
  const runId = spec.runId;
  const attemptId = admission.record.attemptId;

  const deadline = runDeadline(spec.limits?.deadlineAt, input.abortSignal);
  const abortSignal = deadline.signal;
  const inferenceRecorder = createRunInferenceRecorder({
    runId,
    executionAttemptId: attemptId,
    store: input.store,
  });
  try {
    if (abortSignal?.aborted) {
      const record = await input.store.transition(
        runId,
        attemptId,
        "cancelled",
      );
      return { started: false, record };
    }

    let result: RunAgentResult;
    try {
      // getModelInfo resolves unknown ids to a synthetic fallback instead of
      // throwing, so registration must be checked against the catalog itself.
      if (!AVAILABLE_MODELS.some((m) => m.id === spec.model)) {
        throw new Error(`Model is not registered: ${spec.model}`);
      }
      if (!(await stat(spec.environment.cwd)).isDirectory()) {
        throw new Error("Run working directory is not a directory");
      }
      assertCredentialsDeclared(spec, input.credentialManager);

      const session = await createSession({
        id: admission.record.sessionId,
        targets: [spec.target],
        name: spec.runId,
        config: {
          headers: {},
          agentCwd: spec.environment.cwd,
          scopeConstraints: {
            allowedHosts: spec.scope.allowedHosts,
            allowedPorts: spec.scope.allowedPorts,
            strictScope: spec.scope.strictScope,
          },
          allowDestructiveActions: spec.scope.allowDestructiveActions,
          allowRateLimitTesting: spec.scope.allowRateLimitTesting,
          taskDriven: spec.activeTools.some((tool) =>
            TASK_TOOL_NAMES.has(tool),
          ),
          disableSubagents: true,
        },
        inheritEnvironmentConfig: false,
      });

      await input.store.transition(runId, attemptId, "running");

      const contextRecorder = createRunContextRecorder({
        runId,
        attemptId,
        store: {
          getContext: (id) => input.store.getContext(id),
          commitContext: async (id, attempt, revision, change) =>
            input.store.commitContext(id, attempt, revision, change, {
              rootPath: session.rootPath,
              files: await collectSessionEvidence(session),
            }),
        },
      });

      result = await runWithInferenceRecorder(inferenceRecorder, () =>
        runOffensiveSecurityAgent({
          session,
          prompt: spec.prompt,
          model: spec.model,
          ...(spec.system ? { system: spec.system } : {}),
          activeTools: spec.activeTools,
          // Override the SDK's one-step default; persisted limits gate dispatch.
          stopWhen: () => false,
          target: spec.target,
          agentCwd: spec.environment.cwd,
          contextRecorder,
          inferenceRecorder,
          ...(input.authConfig ? { authConfig: input.authConfig } : {}),
          ...(input.credentialManager
            ? { credentialManager: input.credentialManager }
            : {}),
          ...(input.eventBus ? { eventBus: input.eventBus } : {}),
          ...(abortSignal ? { abortSignal } : {}),
        }),
      );
      await inferenceRecorder.flush();
    } catch (error) {
      try {
        await inferenceRecorder.flush();
      } catch (persistenceError) {
        if (error !== persistenceError) {
          error = new AggregateError(
            [error, persistenceError],
            "Recorded run execution and inference persistence failed",
          );
        }
      }
      const status =
        abortSignal?.aborted ||
        (error instanceof Error && error.name === "AbortError")
          ? "cancelled"
          : "failed";
      try {
        await input.store.transition(runId, attemptId, status);
      } catch (settlementError) {
        throw new AggregateError(
          [error, settlementError],
          "Recorded run failed and its status write also failed",
        );
      }
      throw error;
    }

    // Terminal write stays outside the catch: a failed completed/cancelled
    // write must NOT be retried as "failed" — uncertain persistence stays
    // explicit and the last committed status ("running") remains the record.
    const record = await input.store.transition(
      runId,
      attemptId,
      abortSignal?.aborted ? "cancelled" : "completed",
    );
    return { started: true, record, result };
  } finally {
    deadline.dispose();
  }
}
