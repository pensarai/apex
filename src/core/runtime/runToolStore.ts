import type { ToolResultPart } from "ai";
import type { ContextReference } from "./runContext";
import type { EvidenceReference } from "./runEvidence";

export type RecordedToolPolicy =
  | "read_only"
  | "external_effect"
  | "local_mutation"
  | "shell_state";

export interface RecordedToolInput {
  toolCallId: string;
  toolName: string;
  input: unknown;
  policy: RecordedToolPolicy;
}

export interface RecordedToolOperation extends RecordedToolInput {
  schemaVersion: 1;
  operationId: string;
  executionAttemptId: string;
  sequence: number;
  context: ContextReference;
  state: "started" | "settled" | "outcome_unknown";
  output?: ToolResultPart["output"];
  evidence?: { rootPath: string; files: EvidenceReference[] };
  startedAt: string;
  updatedAt: string;
}

export interface RunToolStore {
  initializeToolJournal(
    runId: string,
    executionAttemptId: string,
  ): Promise<void>;
  hasToolJournal(runId: string): Promise<boolean>;
  startToolOperation(
    runId: string,
    executionAttemptId: string,
    input: RecordedToolInput,
  ): Promise<{ created: boolean; operation: RecordedToolOperation }>;
  settleToolOperation(
    runId: string,
    executionAttemptId: string,
    toolCallId: string,
    output: ToolResultPart["output"],
    evidence: { rootPath: string; files: EvidenceReference[] },
  ): Promise<void>;
  markToolOutcomeUnknown(
    runId: string,
    executionAttemptId: string,
    toolCallId: string,
  ): Promise<void>;
  listToolOperations(runId: string): Promise<RecordedToolOperation[]>;
}

export interface ToolExecutionRecorder {
  beforeExecute(
    input: Omit<RecordedToolInput, "policy">,
  ): Promise<
    { kind: "execute" } | { kind: "reuse"; output: ToolResultPart["output"] }
  >;
  settle(toolCallId: string, output: ToolResultPart["output"]): Promise<void>;
  unknown(toolCallId: string): Promise<void>;
  flush(): Promise<void>;
}
