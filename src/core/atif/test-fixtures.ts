import { createHash } from "node:crypto";
import {
  type CaptureDiagnosticV1,
  createContentAddressedAsset,
  type JsonValue,
  NATIVE_ROLLOUT_EVIDENCE_SCHEMA,
  NATIVE_ROLLOUT_EVIDENCE_VERSION,
  type NativeRolloutAttemptLifecycle,
  type NativeRolloutEvidenceEnvelopeV1,
  serializeNativeRolloutEvidence,
} from "../ai/native-rollout-evidence";
import type { AttemptID, IdempotencyKey } from "../id/id";
import type { RecordedNativeRolloutSource } from "./schema";

interface NativeSourceFixtureInput {
  id?: string;
  attemptId?: string;
  idempotencyKey?: string;
  rootAttemptId?: string;
  previousAttemptId?: string;
  sequence?: number;
  sessionId?: string;
  turnId?: string;
  turnIndex?: number;
  lifecycle?: NativeRolloutAttemptLifecycle;
  prompt?: JsonValue[];
  tools?: JsonValue[];
  outputContent?: JsonValue[];
  normalizedOutput?: JsonValue;
  outputAvailable?: boolean;
  nativeInput?: JsonValue;
  nativeOutput?: JsonValue;
  limitations?: CaptureDiagnosticV1[];
  native?: Partial<NativeRolloutEvidenceEnvelopeV1["native"]>;
}

export const defaultPrompt: JsonValue[] = [
  { role: "system", content: "Use only the supplied evidence." },
  {
    role: "user",
    content: [{ type: "text", text: "Summarize the benign fixture." }],
  },
];

export const lookupTool: JsonValue = {
  type: "function",
  name: "lookup_fixture",
  description: "Reads a benign synthetic fixture.",
  inputSchema: {
    type: "object",
    properties: { id: { type: "string" } },
    required: ["id"],
    additionalProperties: false,
  },
};

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function nativeSource(
  input: NativeSourceFixtureInput = {},
): RecordedNativeRolloutSource {
  const attemptId = input.attemptId ?? "atm_fixture_001";
  const sequence = input.sequence ?? 1;
  const rootAttemptId = input.rootAttemptId ?? attemptId;
  const normalizedInput = createContentAddressedAsset(
    {
      prompt: input.prompt ?? defaultPrompt,
      tools: input.tools ?? [],
      includeRawChunks: false,
      temperature: 0,
    },
    "ai-sdk-v3-call-options",
  );
  const normalizedOutput = createContentAddressedAsset(
    input.normalizedOutput ?? {
      content: input.outputContent ?? [
        { type: "text", text: "The fixture is complete." },
      ],
      finishReason: { unified: "stop", raw: "stop" },
      usage: {
        inputTokens: { total: 12, cacheRead: 2 },
        outputTokens: { total: 4 },
      },
      response: { modelId: "effective-model" },
    },
    "ai-sdk-v3-output",
  );
  const outputAvailable = input.outputAvailable ?? true;
  const nativeInput =
    input.nativeInput === undefined
      ? undefined
      : createContentAddressedAsset(input.nativeInput, "provider-request-body");
  const nativeOutput =
    input.nativeOutput === undefined
      ? undefined
      : createContentAddressedAsset(
          input.nativeOutput,
          "provider-response-body",
        );
  const evidence: NativeRolloutEvidenceEnvelopeV1 = {
    schema: NATIVE_ROLLOUT_EVIDENCE_SCHEMA,
    version: NATIVE_ROLLOUT_EVIDENCE_VERSION,
    runId: "run_fixture",
    sessionId: input.sessionId ?? "ses_fixture",
    segmentId: `segment_${String(input.turnIndex ?? 1).padStart(6, "0")}`,
    turnId:
      input.turnId ?? `turn_${String(input.turnIndex ?? 1).padStart(6, "0")}`,
    turnIndex: input.turnIndex ?? 1,
    operationKind: "agent.stream",
    attempt: {
      attemptId: attemptId as AttemptID,
      idempotencyKey: (input.idempotencyKey ??
        "idem_fixture_001") as IdempotencyKey,
      sequence,
      rootAttemptId: rootAttemptId as AttemptID,
      ...(sequence > 1
        ? {
            previousAttemptId: (input.previousAttemptId ??
              rootAttemptId) as AttemptID,
          }
        : {}),
      lifecycle: input.lifecycle ?? "completed",
    },
    requested: { provider: "openai.chat", modelId: "requested-model" },
    effective: { provider: "openai.chat", modelId: "effective-model" },
    boundary: {
      input: {
        normalizedRef: normalizedInput.reference,
        native: nativeInput
          ? { state: "available", value: nativeInput.reference }
          : { state: "omitted", reason: "fixture adapter omitted it" },
      },
      output: {
        normalized: outputAvailable
          ? { state: "available", value: normalizedOutput.reference }
          : { state: "omitted", reason: "fixture output unavailable" },
        native: nativeOutput
          ? { state: "available", value: nativeOutput.reference }
          : { state: "omitted", reason: "fixture adapter omitted it" },
      },
    },
    native: {
      promptTokenIds: {
        state: "unsupported",
        reason: "fixture route does not expose token ids",
      },
      completionTokenIds: {
        state: "unsupported",
        reason: "fixture route does not expose token ids",
      },
      logprobs: {
        state: "omitted",
        reason: "fixture did not request logprobs",
      },
      tokenizer: {
        state: "unsupported",
        reason: "fixture route does not expose tokenizer identity",
      },
      extra: {
        state: "omitted",
        reason: "fixture has no provider extra",
      },
      ...input.native,
    },
    assets: [
      normalizedInput.asset,
      ...(outputAvailable ? [normalizedOutput.asset] : []),
      ...(nativeInput ? [nativeInput.asset] : []),
      ...(nativeOutput ? [nativeOutput.asset] : []),
    ],
    limitations: input.limitations ?? [],
  };
  const bytes = Buffer.from(serializeNativeRolloutEvidence(evidence));
  return {
    id: input.id ?? "source-fixture-001",
    bytes,
    sha256: sha256(bytes),
    sizeBytes: bytes.byteLength,
  };
}
