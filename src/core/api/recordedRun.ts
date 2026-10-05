import { realpath, stat } from "node:fs/promises";
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
import {
  collectSessionEvidence,
  inspectSessionEvidence,
} from "../runtime/runEvidence";
import { createRunInferenceRecorder } from "../runtime/runInference";
import type { RunModelStore } from "../runtime/runModelStore";
import { restoreRunContext } from "../runtime/runRecoveryContext";
import {
  planRunRecovery,
  type RecoveryPlanContext,
} from "../runtime/runRecoveryPlan";
import type { RunRecoveryStore } from "../runtime/runRecoveryStore";
import { RecordedRunSpecSchema, type RunRecord } from "../runtime/runStore";
import type {
  RunToolStore,
  ToolExecutionRecorder,
} from "../runtime/runToolStore";
import { createRunToolRecorder } from "../runtime/runTools";
import {
  create as createSession,
  get as getSession,
  type SessionInfo,
} from "../session";
import { type RunAgentResult, runOffensiveSecurityAgent } from "./offesecAgent";

const TASK_TOOL_NAMES = new Set(["create_task", "update_task", "list_tasks"]);

export type RecordedRunAgentInput = {
  /** Raw (unparsed) run spec — the parsed, normalized form is the only version stored or executed. */
  spec: unknown;
  store: RunModelStore & RunToolStore & RunControlStore & RunRecoveryStore;
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
  const lock = await input.store.acquireExecutionLock(spec.runId);
  try {
    return await executeRecordedRun(input, admission.record);
  } finally {
    lock.release();
  }
}

export type ResumeRecordedAgentInput = Omit<RecordedRunAgentInput, "spec"> & {
  runId: string;
};

export class RunRecoveryBlockedError extends Error {
  constructor(readonly blockers: string[]) {
    super(`Run recovery blocked: ${blockers.join("; ")}`);
    this.name = "RunRecoveryBlockedError";
  }
}

export async function resumeRecordedAgent(
  input: ResumeRecordedAgentInput,
): Promise<RecordedRunOutcome> {
  const { store, runId } = input;
  let lock: Awaited<ReturnType<RunRecoveryStore["acquireExecutionLock"]>>;
  try {
    if (!(await store.getRecoveryEnrollment(runId))) {
      throw new Error("Run predates recovery enrollment; inspection only");
    }
    lock = await store.acquireExecutionLock(runId);
  } catch (error) {
    throw new RunRecoveryBlockedError([
      error instanceof Error ? error.message : String(error),
    ]);
  }
  try {
    let record: RunRecord;
    let continuation: RecordedContinuation;
    try {
      const saved = await store.get(runId);
      if (!saved) throw new Error("Run does not exist");
      record = saved;
      const { spec } = record;
      if (!["running", "paused", "failed"].includes(record.status)) {
        throw new Error(`Run status ${record.status} cannot be recovered`);
      }
      if (input.abortSignal?.aborted) throw new Error("Resume was aborted");
      if (!AVAILABLE_MODELS.some((model) => model.id === spec.model)) {
        throw new Error(`Model is not registered: ${spec.model}`);
      }
      assertCredentialsDeclared(spec, input.credentialManager);
      if (
        spec.limits?.deadlineAt &&
        Date.now() >= Date.parse(spec.limits.deadlineAt)
      ) {
        throw new Error("Run deadline has expired");
      }
      const [
        context,
        attempts,
        operations,
        approvals,
        retries,
        control,
        evidence,
        enrollment,
        recoveries,
      ] = await Promise.all([
        store.getContext(runId),
        store.listModelAttempts(runId),
        store.listToolOperations(runId),
        store.listApprovals(runId),
        store.listRetries(runId),
        store.getControl(runId),
        store.getEvidence(runId),
        store.getRecoveryEnrollment(runId),
        store.listRecoveries(runId),
      ]);
      if (!context) throw new Error("Canonical context checkpoint is missing");
      if (!control || control.intent === "stop")
        throw new Error("Control is missing or stop was requested");
      if (!evidence || !enrollment)
        throw new Error("Evidence inventory or recovery enrollment is missing");
      if (
        spec.limits?.maxModelAttempts !== undefined &&
        attempts.length >= spec.limits.maxModelAttempts
      ) {
        throw new Error("Run model-attempt allowance is exhausted");
      }
      const session = await getSession(record.sessionId);
      if (
        (await realpath(session.rootPath)) !==
          enrollment.environment.sessionRootPath ||
        (await realpath(evidence.rootPath)) !==
          enrollment.environment.sessionRootPath
      ) {
        throw new Error(
          "Session/evidence root does not match recovery enrollment",
        );
      }
      const badEvidence = (
        await inspectSessionEvidence(evidence, evidence.files)
      ).filter((check) => check.status !== "match");
      if (badEvidence.length)
        throw new Error(
          `Evidence is unavailable or changed: ${badEvidence.map((check) => `${check.ref.path} (${check.status})`).join(", ")}`,
        );
      const plan = planRunRecovery({
        record,
        context,
        attempts,
        operations,
        approvals,
        retries,
        recoveries,
      });
      if (!plan.ok) throw new RunRecoveryBlockedError(plan.blockers);
      const restored = restoreRunContext({
        record,
        session,
        context: { ...context, messages: plan.messages },
      });
      continuation = { session, context, ...restored };
      await store.claimRecovery(runId, {
        expectedAttemptId: record.attemptId,
        expectedContext: { epoch: context.epoch, revision: context.revision },
        expectedControlRevision: control.revision,
        reconstruction: plan.reconstruction,
      });
      const claimed = await store.get(runId);
      if (!claimed) throw new Error("Claimed run is missing");
      record = claimed;
    } catch (error) {
      if (error instanceof RunRecoveryBlockedError) throw error;
      throw new RunRecoveryBlockedError([
        error instanceof Error ? error.message : String(error),
      ]);
    }
    return await executeRecordedRun(input, record, continuation);
  } finally {
    lock.release();
  }
}

interface RecordedContinuation {
  session: SessionInfo;
  context: RecoveryPlanContext;
  messages: RecoveryPlanContext["messages"];
  baseSystem: string;
}

async function executeRecordedRun(
  input: Omit<RecordedRunAgentInput, "spec">,
  admitted: RunRecord,
  continuation?: RecordedContinuation,
): Promise<RecordedRunOutcome> {
  const spec = admitted.spec;
  const runId = spec.runId;
  const attemptId = admitted.attemptId;

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
        if (!onlyControlInterruptions(error)) {
          // The enrolled run can never execute; settle failed so a
          // stop-persist failure never leaves it silently admitted.
          try {
            await input.store.transition(runId, attemptId, "failed");
          } catch (settlementError) {
            throw new AggregateError(
              [error, settlementError],
              "Recorded run failed and its status write also failed",
            );
          }
          throw error;
        }
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

      const session =
        continuation?.session ??
        (await createSession({
          id: admitted.sessionId,
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
        }));

      if (!continuation) {
        await input.store.enrollRecovery(runId, attemptId, session.rootPath);
      }
      const runningRecord = await input.store.transition(
        runId,
        attemptId,
        "running",
      );
      if (runningRecord.status === "cancelled") {
        // The store settles a stop-won race as cancelled; nothing may be
        // initialized or executed against the run afterwards. Teardown
        // mirrors the success path so a latched failure surfaces instead
        // of a silently clean return.
        await control.dispose();
        await flushRecorders();
        return { started: false, record: runningRecord };
      }
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
        initial: continuation?.context,
        runId,
        attemptId,
        store: {
          getContext: (id) => input.store.getContext(id),
          commitContext: async (id, attempt, revision, change) => {
            // Pause/stop fence new dispatch, not checkpoints of accepted work.
            for (const flush of [
              () => toolRecorder?.flush(),
              () => control.flush(),
            ]) {
              try {
                await flush();
              } catch (error) {
                if (!onlyControlInterruptions(error)) throw error;
              }
            }
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
          ...(continuation
            ? {
                system: continuation.baseSystem,
                messages: continuation.messages,
              }
            : spec.system
              ? { system: spec.system }
              : {}),
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
