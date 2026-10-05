import { stat } from "node:fs/promises";
import {
  type AIAuthConfig,
  AVAILABLE_MODELS,
  runWithInferenceRecorder,
} from "../ai";
import type { CredentialManager } from "../credentials";
import type { AgentEventBus } from "../eventBus";
import { RunPersistenceError } from "../runtime/persistenceError";
import { composeRecordedExecution } from "../runtime/recordedExecution";
import { createRunContextRecorder } from "../runtime/runContext";
import { createRunControl } from "../runtime/runControl";
import {
  RunControlInterruption,
  type RunControlStore,
} from "../runtime/runControlStore";
import { runDeadline } from "../runtime/runDeadline";
import { collectSessionEvidence } from "../runtime/runEvidence";
import { createRunInferenceRecorder } from "../runtime/runInference";
import type { RunModelStore } from "../runtime/runModelStore";
import { RecordedRunSpecSchema, type RunRecord } from "../runtime/runStore";
import type {
  RunToolStore,
  ToolExecutionRecorder,
} from "../runtime/runToolStore";
import { createRunToolRecorder } from "../runtime/runTools";
import { create as createSession } from "../session";
import { type RunAgentResult, runOffensiveSecurityAgent } from "./offesecAgent";

const TASK_TOOL_NAMES = new Set(["create_task", "update_task", "list_tasks"]);

export type RecordedRunAgentInput = {
  /** Raw (unparsed) run spec — the parsed, normalized form is the only version stored or executed. */
  spec: unknown;
  store: RunModelStore & RunToolStore & RunControlStore;
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
  try {
    await input.store.initializeControl(runId, attemptId);
  } catch (error) {
    deadline.dispose();
    try {
      await input.store.transition(runId, attemptId, "failed");
    } catch (settlementError) {
      throw new AggregateError(
        [error, settlementError],
        "Run control enrollment and status write failed",
      );
    }
    throw error;
  }
  const control = createRunControl({
    runId,
    executionAttemptId: attemptId,
    store: input.store,
    requiredTools: spec.approval?.requiredTools ?? [],
    abortSignal: deadline.signal,
  });
  const abortSignal = control.signal;
  let agentStarted = false;
  const inferenceRecorder = createRunInferenceRecorder({
    runId,
    executionAttemptId: attemptId,
    store: input.store,
  });
  let toolRecorder: ToolExecutionRecorder | undefined;
  const executionRecorder = composeRecordedExecution(
    inferenceRecorder,
    () => toolRecorder,
    () => control,
  );
  const flushRecorders = executionRecorder.flush;
  try {
    if (deadline.signal?.aborted) {
      try {
        await control.flush();
      } catch (error) {
        if (!onlyControlInterruptions(error)) throw error;
      }
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
      await input.store.initializeToolJournal(runId, attemptId);

      const collectEvidence = async () => {
        const files = await collectSessionEvidence(session);
        const previous = new Map(
          (await input.store.getEvidence(runId))?.files.map((ref) => [
            ref.path,
            ref,
          ]),
        );
        return {
          rootPath: session.rootPath,
          // The store merges these into the current inventory. Avoid copying
          // the entire accumulated inventory into every tool receipt.
          files: files.filter((ref) => {
            const known = previous.get(ref.path);
            return known?.sha256 !== ref.sha256 || known.bytes !== ref.bytes;
          }),
        };
      };
      toolRecorder = createRunToolRecorder({
        runId,
        executionAttemptId: attemptId,
        store: input.store,
        collectEvidence,
        beforeTool: control.beforeTool,
      });

      const contextRecorder = createRunContextRecorder({
        runId,
        attemptId,
        store: {
          getContext: (id) => input.store.getContext(id),
          commitContext: async (id, attempt, revision, change) => {
            await toolRecorder?.flush();
            await control.flush();
            return input.store.commitContext(
              id,
              attempt,
              revision,
              change,
              await collectEvidence(),
            );
          },
        },
      });

      await control.beforeDispatch();
      agentStarted = true;
      result = await runWithInferenceRecorder(executionRecorder, () =>
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
          inferenceRecorder: executionRecorder,
          toolExecutionRecorder: toolRecorder,
          ...(input.authConfig ? { authConfig: input.authConfig } : {}),
          ...(input.credentialManager
            ? { credentialManager: input.credentialManager }
            : {}),
          ...(input.eventBus ? { eventBus: input.eventBus } : {}),
          ...(abortSignal ? { abortSignal } : {}),
        }),
      );
      await control.dispose();
      await flushRecorders();
    } catch (error) {
      await control.dispose();
      try {
        await flushRecorders();
      } catch (persistenceError) {
        if (
          error !== persistenceError &&
          !onlyControlInterruptions(persistenceError)
        ) {
          error = new AggregateError(
            [error, persistenceError],
            "Recorded run execution and inference persistence failed",
          );
        }
      }
      if (onlyControlInterruptions(error)) {
        const intent = (await input.store.getControl(runId))?.intent;
        if (intent === "pause" || intent === "stop") {
          const record = await input.store.transition(
            runId,
            attemptId,
            intent === "stop" ? "cancelled" : "paused",
          );
          return { started: agentStarted, record };
        }
      }
      const status =
        !hasPersistenceFailure(error) &&
        (abortSignal?.aborted ||
          (error instanceof Error && error.name === "AbortError"))
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
      abortSignal.aborted || deadline.signal?.aborted
        ? "cancelled"
        : "completed",
    );
    return { started: true, record, result };
  } finally {
    await control.dispose();
    deadline.dispose();
  }
}

function onlyControlInterruptions(error: unknown): boolean {
  return (
    error instanceof RunControlInterruption ||
    (error instanceof AggregateError &&
      error.errors.length > 0 &&
      error.errors.every(onlyControlInterruptions))
  );
}

function hasPersistenceFailure(error: unknown): boolean {
  return (
    error instanceof RunPersistenceError ||
    (error instanceof AggregateError &&
      error.errors.some(hasPersistenceFailure))
  );
}
