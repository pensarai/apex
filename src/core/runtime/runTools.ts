import type { ToolResultPart } from "ai";
import { RunPersistenceError } from "./persistenceError";
import type {
  RecordedToolInput,
  RecordedToolPolicy,
  RunToolStore,
  ToolExecutionRecorder,
} from "./runToolStore";

/** Fixed dispatch policy for the ten recorded-run tools. */
const TOOL_POLICIES = {
  read_file: "read_only",
  list_files: "read_only",
  grep: "read_only",
  list_tasks: "read_only",
  http_request: "external_effect",
  execute_command: "shell_state",
  document_vulnerability: "local_mutation",
  write_plan: "local_mutation",
  create_task: "local_mutation",
  update_task: "local_mutation",
} as const satisfies Record<string, RecordedToolPolicy>;

// Own-property only: prototype chains would resolve "toString" and friends.
function policyFor(toolName: string): RecordedToolPolicy | undefined {
  return Object.hasOwn(TOOL_POLICIES, toolName)
    ? TOOL_POLICIES[toolName as keyof typeof TOOL_POLICIES]
    : undefined;
}

export interface RunToolRecorderOptions {
  /** Logical run id (B1 run spec) — never a session id. */
  runId: string;
  /** Logical execution-attempt id (B1 run record). */
  executionAttemptId: string;
  store: RunToolStore;
  /** Collects evidence references to commit alongside a settled output. */
  collectEvidence: () => Promise<{
    rootPath: string;
    files: import("./runEvidence").EvidenceReference[];
  }>;
}

type BeforeExecuteInput = Omit<RecordedToolInput, "policy">;

export function createRunToolRecorder(
  options: RunToolRecorderOptions,
): ToolExecutionRecorder {
  const { runId, executionAttemptId, store, collectEvidence } = options;
  let latched: RunPersistenceError | undefined;
  let tail: Promise<void> = Promise.resolve();

  const latch = (cause: unknown): RunPersistenceError => {
    latched ??= new RunPersistenceError(cause);
    return latched;
  };

  const enqueue = <T>(op: () => Promise<T>): Promise<T> => {
    const run = tail.then(async () => {
      if (latched) throw latched;
      try {
        return await op();
      } catch (cause) {
        throw latch(cause);
      }
    });
    // Observe every settlement so flush() surfaces errors the caller
    // discarded (the SDK can swallow tool-callback rejections).
    tail = run.then(
      () => {},
      () => {},
    );
    return run;
  };

  // Snapshot synchronously; unserializable values fail closed before dispatch.
  const snapshotInput = <T>(
    value: T,
  ): { ok: true; value: T } | { ok: false } => {
    try {
      return { ok: true, value: structuredClone(value) };
    } catch {
      return { ok: false };
    }
  };

  const beforeExecute = async (
    input: BeforeExecuteInput,
  ): Promise<
    { kind: "execute" } | { kind: "reuse"; output: ToolResultPart["output"] }
  > => {
    if (latched) throw latched;
    const policy = policyFor(input.toolName);
    if (!policy) {
      throw latch(
        new Error(`Tool is not journaled for recorded runs: ${input.toolName}`),
      );
    }
    const snap = snapshotInput(input.input);
    if (!snap.ok) {
      throw latch(
        new Error("Tool input is not serializable and cannot be journaled"),
      );
    }

    const recorded: RecordedToolInput = {
      toolCallId: input.toolCallId,
      toolName: input.toolName,
      input: snap.value,
      policy,
    };

    // The start write is the dispatch gate — it must settle before this
    // call returns, so enqueue and await it directly.
    return enqueue(() =>
      store
        .startToolOperation(runId, executionAttemptId, recorded)
        .then((result) => {
          if (result.created) return { kind: "execute" as const };
          const prior = result.operation;
          if (prior.state === "settled") {
            if (prior.output === undefined) {
              throw new Error(
                `Tool operation ${prior.toolCallId} is settled without an output`,
              );
            }
            return {
              kind: "reuse" as const,
              output: structuredClone(prior.output),
            };
          }
          // started or outcome_unknown: the prior dispatch's effect is not
          // provably repeatable — block, even for read_only tools.
          throw new Error(
            `Tool operation ${prior.toolCallId} is ${prior.state}; refusing re-execution`,
          );
        }),
    );
  };

  const settle = (toolCallId: string, output: ToolResultPart["output"]) => {
    const snap = snapshotInput(output);
    if (!snap.ok) return Promise.reject(latch(new Error("unserializable")));
    const committed: ToolResultPart["output"] = snap.value;
    return enqueue(async () => {
      const evidence = await collectEvidence();
      await store.settleToolOperation(
        runId,
        executionAttemptId,
        toolCallId,
        committed,
        evidence,
      );
    });
  };

  const unknown = (toolCallId: string) =>
    enqueue(() =>
      store.markToolOutcomeUnknown(runId, executionAttemptId, toolCallId),
    );

  const flush = async (): Promise<void> => {
    let last = tail;
    for (;;) {
      await last;
      if (tail === last) break;
      last = tail;
    }
    if (latched) throw latched;
  };

  return { beforeExecute, settle, unknown, flush };
}
