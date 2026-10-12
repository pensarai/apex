import type {
  InferenceAttempt,
  ModelRetryDecision,
  ObservedModelToolCall,
} from "../ai";
import type { RunCheckpointStore } from "./runCheckpointStore";
import type { ContextReference } from "./runContext";

export interface RecordedModelAttempt {
  schemaVersion: 1;
  attempt: InferenceAttempt;
  context: ContextReference | null;
  toolCalls: ObservedModelToolCall[];
  startedAt: string;
  updatedAt: string;
}

export interface RecordedRetry extends ModelRetryDecision {
  sequence: number;
  scheduledAt: string;
  dueAt: string;
}

export interface RunModelStore extends RunCheckpointStore {
  startModelAttempt(
    runId: string,
    executionAttemptId: string,
    attempt: InferenceAttempt,
  ): Promise<void>;
  observeModelToolCall(
    runId: string,
    executionAttemptId: string,
    attemptId: string,
    call: ObservedModelToolCall,
  ): Promise<void>;
  settleModelAttempt(
    runId: string,
    executionAttemptId: string,
    attempt: InferenceAttempt,
  ): Promise<void>;
  recordRetry(
    runId: string,
    executionAttemptId: string,
    decision: ModelRetryDecision,
  ): Promise<void>;
  listModelAttempts(runId: string): Promise<RecordedModelAttempt[]>;
  listRetries(runId: string): Promise<RecordedRetry[]>;
}

export class RunLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunLimitError";
  }
}
