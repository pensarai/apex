import type { ToolResultPart } from "ai";
import { RunPersistenceError } from "./persistenceError";
import {
  type RecordedApproval,
  RunControlConflictError,
  RunControlInterruption,
  type RunControlStore,
} from "./runControlStore";

export interface RunControlOptions {
  runId: string;
  executionAttemptId: string;
  store: RunControlStore;
  /** Tool names whose dispatch requires a persisted operator approval. */
  requiredTools: readonly string[];
  /** Host cancellation (CLI signal, deadline). Persists stop before aborting. */
  abortSignal?: AbortSignal;
  pollIntervalMs?: number;
}

export interface RunControl {
  /** Aborts when a persisted stop is observed or a critical store failure latches. */
  signal: AbortSignal;
  /** Dispatch gate: pause/stop intent or a foreign control owner interrupts. */
  beforeDispatch(): Promise<void>;
  /**
   * Tool gate. Undefined → proceed. A denied required tool resolves the
   * stable blocked result — no tool intent, no effect. Stop interrupts.
   */
  beforeTool(input: {
    toolCallId: string;
    toolName: string;
    input: unknown;
  }): Promise<ToolResultPart["output"] | undefined>;
  /**
   * Drains queued writes; throws the latched storage failure first, then a
   * gate-observed interruption. A merely-polled pause intent never throws.
   */
  flush(): Promise<void>;
  /** Clears timers/listeners and awaits ongoing work; never throws. */
  dispose(): Promise<void>;
}

const DEFAULT_POLL_INTERVAL_MS = 250;
const MAX_STOP_PERSIST_ATTEMPTS = 8;

// Mirrors the legacy approval-gate denial shape so model-visible behavior
// stays consistent between opt-in recorded runs and existing callers.
const DENIED_BY_OPERATOR: ToolResultPart["output"] = {
  type: "json",
  value: { blocked: true, reason: "Denied by operator" },
};

/**
 * Executor-side durable control for one recorded run. Clients write commands
 * to the store; this controller enforces them at dispatch/tool boundaries,
 * polls only to propagate a persisted stop to its own AbortController, and
 * latches terminal causes so flush() surfaces what SDK machinery swallowed.
 */
export function createRunControl(options: RunControlOptions): RunControl {
  const {
    runId,
    executionAttemptId,
    store,
    requiredTools,
    abortSignal,
    pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
  } = options;
  const required = new Set(requiredTools);
  const controller = new AbortController();

  // Gate-observed control state (flush surface only; stop supersedes pause)
  // and storage failures (always retained, always surfaced first — the API
  // must never report a clean pause over a disk failure).
  let interrupted: RunControlInterruption | undefined;
  let interruptedIntent: "pause" | "stop" | "owner" | undefined;
  let persistenceFailure: RunPersistenceError | undefined;

  const latchPersistence = (cause: unknown): RunPersistenceError => {
    persistenceFailure ??=
      cause instanceof RunPersistenceError
        ? cause
        : new RunPersistenceError(cause);
    // A critical store failure aborts in-flight work immediately; gates
    // would throw the latch anyway, but the signal must not wait for the
    // next poll tick.
    controller.abort();
    return persistenceFailure;
  };

  const observeInterruption = (
    error: RunControlInterruption,
    intent?: "pause" | "stop" | "owner",
  ): RunControlInterruption => {
    if (intent === "stop" && interruptedIntent !== "stop") {
      interrupted = error;
      interruptedIntent = intent;
    } else {
      interrupted ??= error;
      interruptedIntent ??= intent;
    }
    return error;
  };

  const persistenceLatched = () => persistenceFailure;

  let tail: Promise<void> = Promise.resolve();
  let disposed = false;
  let stopWrite: Promise<void> | undefined;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  let pollInFlight: Promise<void> | undefined;

  const enqueue = <T>(op: () => Promise<T>): Promise<T> => {
    const run = tail.then(async () => {
      const blocked = persistenceLatched();
      if (blocked) throw blocked;
      try {
        return await op();
      } catch (cause) {
        // The store asserts dispatchability inside its transactions: a
        // pause/stop racing the write surfaces as a control interruption
        // and is retained as such — never wrapped as a storage failure.
        if (cause instanceof RunControlInterruption) {
          throw observeInterruption(cause);
        }
        throw latchPersistence(cause);
      }
    });
    tail = run.then(
      () => {},
      () => {},
    );
    return run;
  };

  const readControl = () =>
    enqueue(async () => {
      const control = await store.getControl(runId);
      if (!control) {
        throw new Error("Run control record is missing");
      }
      return control;
    });

  // CAS retry against the current control; monotonic — observing an
  // existing stop is success. Only a typed revision conflict retries: any
  // other failure is a storage error and propagates after exactly one
  // write attempt. Reads go directly to the store because this runs inside
  // one serialized op — readControl() would enqueue behind the very
  // operation awaiting it and deadlock.
  const persistStop = async (): Promise<void> => {
    for (let attempt = 0; attempt < MAX_STOP_PERSIST_ATTEMPTS; attempt++) {
      const control = await store.getControl(runId);
      if (!control) throw new Error("Run control record is missing");
      // A stale upstream abort must never stop a newer execution owner.
      if (control.executionAttemptId !== executionAttemptId) return;
      if (control.intent === "stop") return;
      try {
        await store.requestControl(runId, "stop", control.revision);
        return;
      } catch (cause) {
        if (!(cause instanceof RunControlConflictError)) throw cause;
        // Revision moved — re-read and retry.
      }
    }
    throw new Error("Persisting the stop intent did not converge");
  };

  const onUpstreamAbort = () => {
    if (disposed || stopWrite) return;
    // The durable record must show stop even if this process dies next;
    // only then may the in-flight work be aborted.
    stopWrite = enqueue(persistStop)
      .catch(() => {})
      .finally(() => {
        controller.abort();
      });
  };

  const poll = async (): Promise<void> => {
    if (disposed || controller.signal.aborted || pollInFlight) return;
    const run = (async () => {
      try {
        const control = await store.getControl(runId);
        if (!control) {
          throw new Error("Run control record is missing");
        }
        if (control.executionAttemptId !== executionAttemptId) {
          // Another attempt owns the run; this executor must not continue.
          observeInterruption(
            new RunControlInterruption(
              `Run control is owned by another execution attempt: ${control.executionAttemptId}`,
            ),
            "owner",
          );
          controller.abort();
        } else if (control.intent === "stop") {
          // Propagation only — the poll never writes or changes status.
          controller.abort();
        }
      } catch (cause) {
        // A control store we can no longer read must not continue execution.
        latchPersistence(cause);
        controller.abort();
      }
    })();
    pollInFlight = run;
    try {
      await run;
    } finally {
      pollInFlight = undefined;
    }
  };

  const sleepOrAbort = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => {
        cleanup();
        resolve();
      }, ms);
      const onAbort = () => {
        cleanup();
        resolve();
      };
      const cleanup = () => {
        clearTimeout(timer);
        controller.signal.removeEventListener("abort", onAbort);
        abortSignal?.removeEventListener("abort", onAbort);
      };
      controller.signal.addEventListener("abort", onAbort, { once: true });
      abortSignal?.addEventListener("abort", onAbort, { once: true });
    });

  const waitForDecision = async (
    approval: RecordedApproval,
  ): Promise<ToolResultPart["output"] | undefined> => {
    let current = approval;
    for (;;) {
      if (current.state === "approved") return undefined;
      if (current.state === "denied") return DENIED_BY_OPERATOR;
      const blocked = persistenceLatched();
      if (blocked) throw blocked;
      if (controller.signal.aborted || abortSignal?.aborted) {
        // The stop transaction denies this approval; the run is dying, so
        // nothing new may execute — never a fabricated approval.
        throw observeInterruption(
          new RunControlInterruption(
            "Run stopped before the approval decision",
          ),
          "stop",
        );
      }
      const [next, control] = await Promise.all([
        enqueue(async () => {
          const record = await store.getApproval(runId, current.approvalId);
          if (!record) throw new Error("Approval record is missing");
          return record;
        }),
        readControl(),
      ]);
      // Pause interrupts the wait too; the pending decision stays durable
      // in the store for whoever resumes.
      assertDispatchable(control);
      current = next;
      await sleepOrAbort(pollIntervalMs);
    }
  };

  const assertDispatchable = (control: {
    executionAttemptId: string;
    intent: string;
  }) => {
    if (control.executionAttemptId !== executionAttemptId) {
      throw observeInterruption(
        new RunControlInterruption(
          `Run control is owned by another execution attempt: ${control.executionAttemptId}`,
        ),
        "owner",
      );
    }
    if (control.intent === "pause") {
      throw observeInterruption(
        new RunControlInterruption("Run paused before dispatch"),
        "pause",
      );
    }
    if (control.intent === "stop") {
      throw observeInterruption(
        new RunControlInterruption("Run stopped before dispatch"),
        "stop",
      );
    }
  };

  const beforeDispatch = async (): Promise<void> => {
    const blocked = persistenceLatched();
    if (blocked) throw blocked;
    // A stop write triggered by an (upstream) abort must be visible to the
    // control read below — the gate observes the persisted stop, not a
    // racier in-memory state.
    if (stopWrite) await stopWrite;
    const control = await readControl();
    assertDispatchable(control);
  };

  const beforeTool = async (input: {
    toolCallId: string;
    toolName: string;
    input: unknown;
  }): Promise<ToolResultPart["output"] | undefined> => {
    const blocked = persistenceLatched();
    if (blocked) throw blocked;
    if (stopWrite) await stopWrite;
    // Snapshot the validated input only: the approval binds exact bytes, so
    // caller mutation during the write cannot change what a decision
    // authorizes.
    const committedInput = structuredClone(input.input);
    const control = await readControl();
    assertDispatchable(control);
    if (!required.has(input.toolName)) return undefined;
    const approval = await enqueue(() =>
      store.requestApproval(runId, executionAttemptId, {
        toolCallId: input.toolCallId,
        toolName: input.toolName,
        input: committedInput,
      }),
    );
    return waitForDecision(approval);
  };

  const flush = async (): Promise<void> => {
    let last = tail;
    for (;;) {
      await last;
      if (tail === last) break;
      last = tail;
    }
    // Storage failure outranks any interruption: a disk failure must never
    // read back as a clean paused/cancelled outcome.
    if (persistenceFailure) throw persistenceFailure;
    if (interrupted) throw interrupted;
  };

  const dispose = async (): Promise<void> => {
    disposed = true;
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
    abortSignal?.removeEventListener("abort", onUpstreamAbort);
    if (pollInFlight) await pollInFlight;
    let last = tail;
    for (;;) {
      await last;
      if (tail === last) break;
      last = tail;
    }
  };

  if (abortSignal) {
    abortSignal.addEventListener("abort", onUpstreamAbort, { once: true });
    if (abortSignal.aborted) onUpstreamAbort();
  }

  // A stop persisted while this process was down must abort immediately.
  void poll();
  pollTimer = setInterval(() => {
    void poll();
  }, pollIntervalMs);
  pollTimer.unref?.();

  return {
    signal: controller.signal,
    beforeDispatch,
    beforeTool,
    flush,
    dispose,
  };
}
