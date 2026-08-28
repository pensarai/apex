import { shouldRecordAiPayloads } from "./index";

/**
 * Structurally the AI SDK's `TelemetrySettings` (the package does not
 * re-export the type). Passed as `experimental_telemetry` on model calls.
 */
export interface AiTelemetrySettings {
  isEnabled: boolean;
  recordInputs: boolean;
  recordOutputs: boolean;
  /** Stable, low-cardinality operation identifier (`apex.<area>.<verb>`). */
  functionId: string;
  metadata?: Record<string, string>;
}

/** Stable operation identifiers for every model-call helper. */
export type AiTelemetryOperation =
  | "apex.agent.stream"
  | "apex.structured.generate"
  | "apex.context.summarize"
  | "apex.tool.repair";

export interface CreateAiTelemetryInput {
  operation: AiTelemetryOperation;
  sessionId?: string;
  runId?: string;
  agentId?: string;
}

/**
 * One builder for every model call's telemetry — identical payload policy
 * everywhere. Full payload capture (`recordInputs`/`recordOutputs`) is
 * opt-in via `AI_TRACE_RECORD_PAYLOADS=true` and never defaults on.
 *
 * ⚠️ Full mode exports sensitive data to the configured OTLP backend,
 * including customer source code, credentials, cookies, authorization
 * headers, attack targets, and model reasoning. Off by default.
 */
export function createAiTelemetrySettings(
  input: CreateAiTelemetryInput,
): AiTelemetrySettings {
  const recordPayloads = shouldRecordAiPayloads();
  const metadata: Record<string, string> = {};
  if (input.sessionId) metadata.sessionId = input.sessionId;
  if (input.runId) metadata.runId = input.runId;
  if (input.agentId) metadata.agentId = input.agentId;
  return {
    isEnabled: true,
    recordInputs: recordPayloads,
    recordOutputs: recordPayloads,
    // Model ids belong in span attributes (ai.model.id), never in the
    // operation name — a per-model functionId is unbounded cardinality.
    functionId: input.operation,
    ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
  };
}
