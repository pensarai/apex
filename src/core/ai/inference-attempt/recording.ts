import { AsyncLocalStorage } from "node:async_hooks";
import type { InferenceAttempt } from "./envelope";

export interface ObservedModelToolCall {
  toolCallId: string;
  toolName: string;
}

export interface ModelRetryDecision {
  authority:
    | "stream-rate-limit"
    | "stream-idle"
    | "object-rate-limit"
    | "context-restart";
  count: number;
  maxRetries: number;
  delayMs: number;
}

export interface InferenceRecorder {
  readonly runId: string;
  beforeDispatch(attempt: InferenceAttempt): Promise<void>;
  beforeToolCall(attemptId: string, call: ObservedModelToolCall): Promise<void>;
  // Synchronous finalizers enqueue settlement; flush owns error propagation.
  settle(attempt: InferenceAttempt): void;
  retry(decision: ModelRetryDecision): Promise<void>;
  flush(): Promise<void>;
}

const recorderContext = new AsyncLocalStorage<InferenceRecorder | undefined>();

export function runWithInferenceRecorder<T>(
  recorder: InferenceRecorder | undefined,
  operation: () => T,
): T {
  return recorderContext.run(recorder, operation);
}

export function getInferenceRecorder(binding?: {
  inferenceRecorder?: InferenceRecorder;
}): InferenceRecorder | undefined {
  // Explicit undefined isolates a child; omission preserves low-level ALS callers.
  return binding && "inferenceRecorder" in binding
    ? binding.inferenceRecorder
    : recorderContext.getStore();
}
