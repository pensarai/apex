import type {
  InferenceAttempt,
  InferenceRecorder,
  ModelRetryDecision,
  ObservedModelToolCall,
} from "../ai";
import { RunPersistenceError } from "./persistenceError";
import { RunControlInterruption } from "./runControlStore";
import { RunLimitError, type RunModelStore } from "./runModelStore";

interface RunInferenceRecorderOptions {
  runId: string;
  executionAttemptId: string;
  store: RunModelStore;
}

// Serialize critical writes; the store owns execution identity and limits.
export function createRunInferenceRecorder(
  options: RunInferenceRecorderOptions,
): InferenceRecorder {
  const { runId, executionAttemptId, store } = options;
  let latched: Error | undefined;
  let tail: Promise<void> = Promise.resolve();

  const latch = (cause: unknown): Error => {
    if (latched) return latched;
    latched =
      cause instanceof RunLimitError ||
      cause instanceof RunPersistenceError ||
      cause instanceof RunControlInterruption
        ? cause
        : new RunPersistenceError(cause);
    return latched;
  };

  const enqueue = (op: () => Promise<void>): Promise<void> => {
    const run = tail.then(async () => {
      if (latched) throw latched;
      try {
        await op();
      } catch (cause) {
        throw latch(cause);
      }
    });
    // Observe every settlement so flush() can surface errors the caller
    // (or the SDK's terminal callbacks) discarded.
    tail = run.then(
      () => {},
      () => {},
    );
    return run;
  };

  const snapshot = <T>(value: T): { ok: true; value: T } | { ok: false } => {
    try {
      return { ok: true, value: structuredClone(value) };
    } catch {
      return { ok: false };
    }
  };

  const beforeDispatch = (attempt: InferenceAttempt): Promise<void> => {
    const snap = snapshot(attempt);
    if (!snap.ok) return Promise.reject(latch(new Error("clone failed")));
    return enqueue(() =>
      store.startModelAttempt(runId, executionAttemptId, snap.value),
    );
  };

  const beforeToolCall = (
    attemptId: string,
    call: ObservedModelToolCall,
  ): Promise<void> => {
    const snap = snapshot(call);
    if (!snap.ok) return Promise.reject(latch(new Error("clone failed")));
    return enqueue(() =>
      store.observeModelToolCall(
        runId,
        executionAttemptId,
        attemptId,
        snap.value,
      ),
    );
  };

  const retry = (decision: ModelRetryDecision): Promise<void> => {
    const snap = snapshot(decision);
    if (!snap.ok) return Promise.reject(latch(new Error("clone failed")));
    return enqueue(() =>
      store.recordRetry(runId, executionAttemptId, snap.value),
    );
  };

  // Sync terminal: enqueue the critical settle write, never throw. The
  // rejection is observed on the tail; flush() is the enforcement point.
  const settle = (attempt: InferenceAttempt): void => {
    const snap = snapshot(attempt);
    if (!snap.ok) {
      latch(new Error("clone failed"));
      return;
    }
    void enqueue(() =>
      store.settleModelAttempt(runId, executionAttemptId, snap.value),
    );
  };

  const flush = async (): Promise<void> => {
    let last = tail;
    for (;;) {
      await last;
      if (tail === last) break;
      last = tail;
    }
    if (latched) throw latched;
  };

  return {
    runId,
    beforeDispatch,
    beforeToolCall,
    settle,
    retry,
    flush,
  };
}
