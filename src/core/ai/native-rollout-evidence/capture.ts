import { AsyncLocalStorage } from "node:async_hooks";
import {
  APICallError,
  type LanguageModelV3,
  type LanguageModelV3CallOptions,
  type LanguageModelV3GenerateResult,
  type LanguageModelV3StreamPart,
  type LanguageModelV3StreamResult,
  type LanguageModelV3Usage,
} from "@ai-sdk/provider";
import {
  type AttemptUsageInput,
  type InferenceAttempt,
  type InferenceAttemptHandle,
  startInferenceAttempt,
} from "../inference-attempt";
import {
  createContentAddressedAsset,
  hashCanonicalJson,
  NativeRolloutContentError,
  stringifyCanonicalJson,
  toJsonValue,
} from "./content";
import { extractNativeSamplingEvidence } from "./provider-metadata";
import type {
  CaptureDiagnosticV1,
  ContentAddressedAssetV1,
  ContentReferenceV1,
  EvidenceAvailability,
  JsonValue,
  NativeRolloutAttemptLifecycle,
  NativeRolloutAttemptSink,
  NativeRolloutCaptureLimits,
  NativeRolloutCaptureReportV1,
  NativeRolloutEvidenceEnvelopeV1,
  NativeRolloutEvidenceSink,
  NativeRolloutModelContext,
} from "./schema";
import {
  NATIVE_ROLLOUT_CAPTURE_REPORT_SCHEMA,
  NATIVE_ROLLOUT_EVIDENCE_SCHEMA,
  NATIVE_ROLLOUT_EVIDENCE_VERSION,
} from "./schema";
import {
  parseNativeRolloutEvidence,
  serializeNativeRolloutEvidence,
} from "./validate";

export const DEFAULT_NATIVE_ROLLOUT_CAPTURE_LIMITS: NativeRolloutCaptureLimits =
  {
    maxAssetBytes: 1_048_576,
    maxEnvelopeBytes: 2_097_152,
    maxPendingRecords: 32,
    maxDiagnostics: 32,
    sinkTimeoutMs: 2_000,
  };

export interface CreateNativeRolloutEvidenceCaptureInput {
  enabled?: boolean;
  runId: string;
  sink?: NativeRolloutEvidenceSink;
  attemptSink?: NativeRolloutAttemptSink;
  limits?: Partial<NativeRolloutCaptureLimits>;
}

export interface NativeRolloutEvidenceCapture {
  run<T>(fn: () => T): T;
  flush(): Promise<NativeRolloutCaptureReportV1>;
}

interface CaptureStore {
  enabled: boolean;
  runId: string;
  sink?: NativeRolloutEvidenceSink;
  attemptSink?: NativeRolloutAttemptSink;
  limits: NativeRolloutCaptureLimits;
  diagnostics: CaptureDiagnosticV1[];
  attemptedRecords: number;
  writtenRecords: number;
  droppedRecords: number;
  deliveryUnknownRecords: number;
  pendingWrites: Set<Promise<void>>;
  activeSinkWrites: Set<Promise<void>>;
  activeAttemptWrites: Set<Promise<void>>;
  flushers: Set<() => void>;
  nextSegment: number;
  nextTurnBySession: Map<string, number>;
  interrupted: boolean;
}

interface OperationContext {
  operationKind: NativeRolloutModelContext["operationKind"];
  sessionId?: string;
  invocation: symbol;
}

interface ResolvedOperationContext {
  model: NativeRolloutModelContext;
  invocation: symbol;
}

interface TurnIdentity {
  segmentId: string;
  turnId: string;
  turnIndex: number;
}

interface PreparedInput {
  normalizedRef: ContentReferenceV1;
  assets: ContentAddressedAssetV1[];
  limitations: CaptureDiagnosticV1[];
}

interface AttemptCapture {
  turn: TurnIdentity;
  attempt: InferenceAttemptHandle;
  modelContext: NativeRolloutModelContext;
  provider: string;
  modelId: string;
  input: PreparedInput;
  nativeInput?: unknown;
}

interface PendingFailure {
  capture: AttemptCapture;
  nativeInput?: unknown;
}

interface StreamCollector {
  parts: JsonValue[];
  rawParts: JsonValue[];
  byteLength: number;
  rawByteLength: number;
  truncated: boolean;
  rawTruncated: boolean;
  sawError: boolean;
  sawFinish: boolean;
  finishReason?: string;
  providerMetadata?: unknown;
  usage?: LanguageModelV3Usage;
  responseId?: string;
  responseModelId?: string;
}

export interface NativeRolloutSessionContext {
  sessionId: string;
  parentSessionId?: string;
  parentToolCallId?: string;
}

const captureStore = new AsyncLocalStorage<CaptureStore>();
const operationStore = new AsyncLocalStorage<OperationContext>();
const sessionStore = new AsyncLocalStorage<NativeRolloutSessionContext>();

function positiveInteger(name: string, value: number): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function integerAtLeast(name: string, value: number, minimum: number): number {
  positiveInteger(name, value);
  if (value < minimum) {
    throw new Error(`${name} must be at least ${minimum}`);
  }
  return value;
}

function resolveLimits(
  input?: Partial<NativeRolloutCaptureLimits>,
): NativeRolloutCaptureLimits {
  const merged = { ...DEFAULT_NATIVE_ROLLOUT_CAPTURE_LIMITS, ...input };
  return {
    maxAssetBytes: integerAtLeast("maxAssetBytes", merged.maxAssetBytes, 256),
    maxEnvelopeBytes: positiveInteger(
      "maxEnvelopeBytes",
      merged.maxEnvelopeBytes,
    ),
    maxPendingRecords: positiveInteger(
      "maxPendingRecords",
      merged.maxPendingRecords,
    ),
    maxDiagnostics: positiveInteger("maxDiagnostics", merged.maxDiagnostics),
    sinkTimeoutMs: positiveInteger("sinkTimeoutMs", merged.sinkTimeoutMs),
  };
}

function addDiagnostic(
  store: CaptureStore,
  diagnostic: CaptureDiagnosticV1,
): void {
  if (store.diagnostics.length < store.limits.maxDiagnostics) {
    store.diagnostics.push(diagnostic);
  }
}

function markInterrupted<T>(store: CaptureStore, value: T): T {
  if (
    value &&
    (typeof value === "object" || typeof value === "function") &&
    "then" in value
  ) {
    return Promise.resolve(value).catch((error) => {
      store.interrupted = true;
      throw error;
    }) as T;
  }
  return value;
}

export function createNativeRolloutEvidenceCapture(
  input: CreateNativeRolloutEvidenceCaptureInput,
): NativeRolloutEvidenceCapture {
  if (!input.runId) throw new Error("runId is required");
  const enabled = input.enabled ?? false;
  if (enabled && !input.sink) {
    throw new Error("an evidence sink is required when capture is enabled");
  }
  const store: CaptureStore = {
    enabled,
    runId: input.runId,
    sink: input.sink,
    attemptSink: input.attemptSink,
    limits: resolveLimits(input.limits),
    diagnostics: [],
    attemptedRecords: 0,
    writtenRecords: 0,
    droppedRecords: 0,
    deliveryUnknownRecords: 0,
    pendingWrites: new Set(),
    activeSinkWrites: new Set(),
    activeAttemptWrites: new Set(),
    flushers: new Set(),
    nextSegment: 1,
    nextTurnBySession: new Map(),
    interrupted: false,
  };

  return {
    run<T>(fn: () => T): T {
      if (!store.enabled) return fn();
      try {
        return markInterrupted(store, captureStore.run(store, fn));
      } catch (error) {
        store.interrupted = true;
        throw error;
      }
    },
    async flush(): Promise<NativeRolloutCaptureReportV1> {
      for (const flush of [...store.flushers]) flush();
      while (store.pendingWrites.size > 0) {
        await Promise.all([...store.pendingWrites]);
      }
      const state = !store.enabled
        ? "disabled"
        : store.interrupted
          ? "interrupted"
          : store.droppedRecords > 0 ||
              store.deliveryUnknownRecords > 0 ||
              store.diagnostics.length > 0
            ? "limited"
            : "complete";
      return {
        schema: NATIVE_ROLLOUT_CAPTURE_REPORT_SCHEMA,
        version: NATIVE_ROLLOUT_EVIDENCE_VERSION,
        runId: store.runId,
        state,
        attemptedRecords: store.attemptedRecords,
        writtenRecords: store.writtenRecords,
        droppedRecords: store.droppedRecords,
        deliveryUnknownRecords: store.deliveryUnknownRecords,
        diagnostics: [...store.diagnostics],
      };
    },
  };
}

export function runWithNativeRolloutOperation<T>(
  context: Omit<OperationContext, "invocation">,
  fn: () => T,
): T {
  return operationStore.run(
    { ...context, invocation: Symbol("model-call") },
    fn,
  );
}

export function runWithNativeRolloutSession<T>(
  context: NativeRolloutSessionContext,
  fn: () => T,
): T {
  if (
    (context.parentSessionId === undefined) !==
    (context.parentToolCallId === undefined)
  ) {
    throw new Error(
      "parentSessionId and parentToolCallId must be supplied together",
    );
  }
  return sessionStore.run(context, fn);
}

function boundedSinkWrite(
  operation: Promise<void>,
  controller: AbortController,
  timeoutMs: number,
): Promise<"written" | "unknown"> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<"unknown">((resolve) => {
    timer = setTimeout(() => {
      controller.abort(new Error("native evidence sink timed out"));
      resolve("unknown");
    }, timeoutMs);
  });
  return Promise.race([
    operation.then(() => "written" as const),
    timeout,
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function queueEnvelope(
  store: CaptureStore,
  envelope: NativeRolloutEvidenceEnvelopeV1,
): void {
  store.attemptedRecords += 1;
  let parsed: NativeRolloutEvidenceEnvelopeV1;
  let byteLength: number;
  try {
    parsed = parseNativeRolloutEvidence(envelope);
    byteLength = Buffer.byteLength(serializeNativeRolloutEvidence(parsed));
  } catch {
    store.droppedRecords += 1;
    addDiagnostic(store, {
      code: "invalid_record",
      message: "a captured attempt failed evidence validation",
    });
    return;
  }
  if (byteLength > store.limits.maxEnvelopeBytes) {
    store.droppedRecords += 1;
    addDiagnostic(store, {
      code: "envelope_limit",
      message: "a captured attempt exceeded the envelope byte limit",
    });
    return;
  }
  if (store.activeSinkWrites.size >= store.limits.maxPendingRecords) {
    store.droppedRecords += 1;
    addDiagnostic(store, {
      code: "queue_limit",
      message: "the evidence sink queue reached its record limit",
    });
    return;
  }

  const controller = new AbortController();
  const write = Promise.resolve()
    .then(() => store.sink?.write(parsed, { signal: controller.signal }))
    .finally(() => {
      store.activeSinkWrites.delete(write);
    });
  store.activeSinkWrites.add(write);
  const pending = boundedSinkWrite(
    write,
    controller,
    store.limits.sinkTimeoutMs,
  )
    .then((outcome) => {
      if (outcome === "written") {
        store.writtenRecords += 1;
      } else {
        store.deliveryUnknownRecords += 1;
        addDiagnostic(store, {
          code: "sink_delivery_unknown",
          message:
            "the evidence sink did not confirm persistence before its deadline",
        });
      }
    })
    .catch(() => {
      store.droppedRecords += 1;
      addDiagnostic(store, {
        code: "sink_failure",
        message: "the evidence sink did not persist a captured attempt",
      });
    })
    .finally(() => {
      store.pendingWrites.delete(pending);
    });
  store.pendingWrites.add(pending);
}

function queueAttempt(store: CaptureStore, attempt: InferenceAttempt): void {
  if (!store.attemptSink) return;
  if (
    Buffer.byteLength(JSON.stringify(attempt)) > store.limits.maxEnvelopeBytes
  ) {
    addDiagnostic(store, {
      code: "attempt_envelope_limit",
      message: "an inference-attempt event exceeded the envelope byte limit",
    });
    return;
  }
  if (store.activeAttemptWrites.size >= store.limits.maxPendingRecords) {
    addDiagnostic(store, {
      code: "attempt_queue_limit",
      message: "the inference-attempt sink queue reached its record limit",
    });
    return;
  }

  const controller = new AbortController();
  const write = Promise.resolve()
    .then(() =>
      store.attemptSink?.write(attempt, { signal: controller.signal }),
    )
    .finally(() => {
      store.activeAttemptWrites.delete(write);
    });
  store.activeAttemptWrites.add(write);
  const pending = boundedSinkWrite(
    write,
    controller,
    store.limits.sinkTimeoutMs,
  )
    .then((outcome) => {
      if (outcome === "unknown") {
        addDiagnostic(store, {
          code: "attempt_sink_delivery_unknown",
          message:
            "the inference-attempt sink did not confirm persistence before its deadline",
        });
      }
    })
    .catch(() => {
      addDiagnostic(store, {
        code: "attempt_sink_failure",
        message: "the inference-attempt sink rejected an event",
      });
    })
    .finally(() => {
      store.pendingWrites.delete(pending);
    });
  store.pendingWrites.add(pending);
}

function addAsset(
  assets: Map<string, ContentAddressedAssetV1>,
  asset: ContentAddressedAssetV1,
): void {
  assets.set(asset.ref, asset);
}

function requiredContent(
  store: CaptureStore,
  value: unknown,
  representation: string,
): PreparedInput {
  const limitations: CaptureDiagnosticV1[] = [];
  let normalized: JsonValue;
  try {
    normalized = toJsonValue(value);
  } catch (error) {
    normalized = {
      capture: "unavailable",
      reason:
        error instanceof NativeRolloutContentError
          ? error.message
          : "content normalization failed",
    };
    limitations.push({
      code: "content_unavailable",
      message: "normalized boundary input could not be represented as JSON",
      field: "boundary.input.normalizedRef",
    });
  }

  const measured = hashCanonicalJson(normalized);
  if (measured.byteLength > store.limits.maxAssetBytes) {
    normalized = {
      capture: "truncated",
      original: measured,
    };
    representation = `${representation};truncated`;
    limitations.push({
      code: "asset_limit",
      message: "normalized boundary input exceeded the asset byte limit",
      field: "boundary.input.normalizedRef",
    });
  }
  const { asset, reference } = createContentAddressedAsset(
    normalized,
    representation,
  );
  return { normalizedRef: reference, assets: [asset], limitations };
}

function optionalContent(
  store: CaptureStore,
  value: unknown,
  representation: string,
  absent: "omitted" | "unsupported",
  absentReason: string,
): {
  availability: EvidenceAvailability<ContentReferenceV1>;
  assets: ContentAddressedAssetV1[];
  limitations: CaptureDiagnosticV1[];
} {
  if (value === undefined) {
    return {
      availability: { state: absent, reason: absentReason },
      assets: [],
      limitations: [],
    };
  }
  let normalized: JsonValue;
  try {
    normalized = toJsonValue(value);
  } catch {
    return {
      availability: {
        state: "omitted",
        reason: "the exposed content could not be represented as JSON",
      },
      assets: [],
      limitations: [
        {
          code: "content_unavailable",
          message: "exposed boundary content could not be represented as JSON",
        },
      ],
    };
  }
  const measured = hashCanonicalJson(normalized);
  if (measured.byteLength > store.limits.maxAssetBytes) {
    return {
      availability: {
        state: "truncated",
        reason: "the exposed content exceeded the asset byte limit",
        observed: measured,
      },
      assets: [],
      limitations: [
        {
          code: "asset_limit",
          message: "exposed boundary content exceeded the asset byte limit",
        },
      ],
    };
  }
  const { asset, reference } = createContentAddressedAsset(
    normalized,
    representation,
  );
  return {
    availability: { state: "available", value: reference },
    assets: [asset],
    limitations: [],
  };
}

function normalizedCallOptions(options: LanguageModelV3CallOptions): unknown {
  return {
    prompt: options.prompt,
    maxOutputTokens: options.maxOutputTokens,
    temperature: options.temperature,
    stopSequences: options.stopSequences,
    topP: options.topP,
    topK: options.topK,
    presencePenalty: options.presencePenalty,
    frequencyPenalty: options.frequencyPenalty,
    responseFormat: options.responseFormat,
    seed: options.seed,
    tools: options.tools,
    toolChoice: options.toolChoice,
    includeRawChunks: options.includeRawChunks,
    providerOptions: options.providerOptions,
  };
}

function allocateTurn(
  store: CaptureStore,
  context: NativeRolloutModelContext,
): TurnIdentity {
  const sessionKey = context.sessionId ?? "";
  const turnIndex = (store.nextTurnBySession.get(sessionKey) ?? 0) + 1;
  store.nextTurnBySession.set(sessionKey, turnIndex);
  const segment = store.nextSegment++;
  return {
    segmentId: `segment_${segment.toString().padStart(6, "0")}`,
    turnId: `turn_${turnIndex.toString().padStart(6, "0")}`,
    turnIndex,
  };
}

function beginAttempt(
  store: CaptureStore,
  context: NativeRolloutModelContext,
  provider: string,
  modelId: string,
  options: LanguageModelV3CallOptions,
  retry?: PendingFailure,
): AttemptCapture {
  const input = requiredContent(
    store,
    normalizedCallOptions(options),
    "ai-sdk-v3-call-options",
  );
  if (!retry) {
    const turn = allocateTurn(store, context);
    const capture: AttemptCapture = {
      turn,
      attempt: startInferenceAttempt({
        operationKind: context.operationKind,
        requested: {
          provider,
          modelId: context.requestedModelId,
          ...(context.transport ? { transport: context.transport } : {}),
        },
        effective: {
          provider,
          modelId,
          ...(context.transport ? { transport: context.transport } : {}),
        },
        attribution: {
          runId: store.runId,
          ...(context.sessionId ? { sessionId: context.sessionId } : {}),
        },
      }),
      modelContext: context,
      provider,
      modelId,
      input,
    };
    queueAttempt(store, capture.attempt.started);
    return capture;
  }
  const capture: AttemptCapture = {
    turn: {
      ...retry.capture.turn,
    },
    attempt: retry.capture.attempt.retry(),
    modelContext: context,
    provider,
    modelId,
    input,
  };
  queueAttempt(store, capture.attempt.started);
  return capture;
}

function errorRequestBody(error: unknown): unknown {
  return APICallError.isInstance(error) ? error.requestBodyValues : undefined;
}

function emitAttempt(
  store: CaptureStore,
  capture: AttemptCapture,
  input: {
    lifecycle: NativeRolloutAttemptLifecycle;
    nativeInput?: unknown;
    normalizedOutput?: unknown;
    normalizedOutputState?: "available" | "truncated" | "interrupted";
    nativeOutput?: unknown;
    nativeOutputAbsent?: "omitted" | "unsupported";
    nativeOutputReason?: string;
    providerMetadata?: unknown;
    usage?: LanguageModelV3Usage;
    providerRequestId?: string;
    effectiveModelId?: string;
    limitations?: CaptureDiagnosticV1[];
  },
): void {
  const assets = new Map<string, ContentAddressedAssetV1>();
  for (const asset of capture.input.assets) addAsset(assets, asset);
  const limitations = [
    ...capture.input.limitations,
    ...(input.limitations ?? []),
  ];

  const nativeInput = optionalContent(
    store,
    input.nativeInput,
    "provider-request-body",
    "omitted",
    "the provider did not expose its serialized request body",
  );
  for (const asset of nativeInput.assets) addAsset(assets, asset);
  limitations.push(...nativeInput.limitations);

  const normalizedOutput = optionalContent(
    store,
    input.normalizedOutput,
    "ai-sdk-v3-output",
    "omitted",
    "the provider call returned no normalized output",
  );
  for (const asset of normalizedOutput.assets) addAsset(assets, asset);
  limitations.push(...normalizedOutput.limitations);
  let normalizedOutputAvailability = normalizedOutput.availability;
  if (
    normalizedOutputAvailability.state === "available" &&
    input.normalizedOutputState &&
    input.normalizedOutputState !== "available"
  ) {
    normalizedOutputAvailability = {
      state: input.normalizedOutputState,
      reason:
        input.normalizedOutputState === "truncated"
          ? "the bounded collector omitted later output parts"
          : "the provider output ended before a complete terminal result",
      partial: normalizedOutputAvailability.value,
    };
  }

  const nativeOutput = optionalContent(
    store,
    input.nativeOutput,
    "provider-response-body",
    input.nativeOutputAbsent ?? "omitted",
    input.nativeOutputReason ??
      "the provider did not expose its native response body",
  );
  for (const asset of nativeOutput.assets) addAsset(assets, asset);
  limitations.push(...nativeOutput.limitations);

  const sampling = extractNativeSamplingEvidence({
    provider: capture.provider,
    providerMetadata: input.providerMetadata,
  });
  if (
    (input.lifecycle === "aborted" || input.lifecycle === "partial") &&
    sampling.logprobs.state === "omitted"
  ) {
    sampling.logprobs = {
      state: "interrupted",
      reason: "the stream ended before completion logprobs were observed",
    };
  }

  const usage: AttemptUsageInput = {
    transport: "sdk-normalized",
    usage: input.usage,
    providerMetadata: input.providerMetadata,
    providerRequestId: input.providerRequestId,
    effective: {
      provider: capture.provider,
      modelId: input.effectiveModelId ?? capture.modelId,
      ...(capture.modelContext.transport
        ? { transport: capture.modelContext.transport }
        : {}),
    },
  };
  const settle = (attemptUsage?: AttemptUsageInput) => {
    switch (input.lifecycle) {
      case "completed":
        return capture.attempt.complete(attemptUsage);
      case "failed":
        return capture.attempt.fail(attemptUsage);
      case "partial":
        return capture.attempt.partial(attemptUsage);
      case "aborted":
        return capture.attempt.abort(attemptUsage);
      case "retried":
        return capture.attempt.retried(attemptUsage);
    }
  };
  let attempt: InferenceAttempt;
  try {
    attempt = settle(usage);
  } catch {
    addDiagnostic(store, {
      code: "attempt_usage_unavailable",
      message: "the inference-attempt observer could not normalize usage",
    });
    attempt = settle();
  }
  queueAttempt(store, attempt);

  queueEnvelope(store, {
    schema: NATIVE_ROLLOUT_EVIDENCE_SCHEMA,
    version: NATIVE_ROLLOUT_EVIDENCE_VERSION,
    runId: store.runId,
    ...(capture.modelContext.sessionId
      ? { sessionId: capture.modelContext.sessionId }
      : {}),
    ...(capture.modelContext.parentSessionId &&
    capture.modelContext.parentToolCallId
      ? {
          parent: {
            sessionId: capture.modelContext.parentSessionId,
            toolCallId: capture.modelContext.parentToolCallId,
          },
        }
      : {}),
    segmentId: capture.turn.segmentId,
    turnId: capture.turn.turnId,
    turnIndex: capture.turn.turnIndex,
    operationKind: capture.modelContext.operationKind,
    attempt: {
      attemptId: attempt.attemptId,
      idempotencyKey: attempt.idempotencyKey,
      sequence: attempt.lineage.sequence,
      rootAttemptId: attempt.attribution.rootAttemptId,
      ...(attempt.lineage.previousAttemptId
        ? { previousAttemptId: attempt.lineage.previousAttemptId }
        : {}),
      lifecycle: input.lifecycle,
    },
    requested: {
      provider: capture.provider,
      modelId: capture.modelContext.requestedModelId,
      ...(capture.modelContext.transport
        ? { transport: capture.modelContext.transport }
        : {}),
    },
    effective: {
      provider: capture.provider,
      modelId: input.effectiveModelId ?? capture.modelId,
      ...(capture.modelContext.transport
        ? { transport: capture.modelContext.transport }
        : {}),
    },
    boundary: {
      input: {
        normalizedRef: capture.input.normalizedRef,
        native: nativeInput.availability,
      },
      output: {
        normalized: normalizedOutputAvailability,
        native: nativeOutput.availability,
      },
    },
    native: sampling,
    assets: [...assets.values()],
    limitations,
  });
}

function safeEmitAttempt(
  store: CaptureStore,
  capture: AttemptCapture,
  input: Parameters<typeof emitAttempt>[2],
): void {
  try {
    emitAttempt(store, capture, input);
  } catch {
    store.attemptedRecords += 1;
    store.droppedRecords += 1;
    addDiagnostic(store, {
      code: "capture_failure",
      message: "the passive collector could not assemble an attempt record",
    });
  }
}

function collectStreamPart(
  store: CaptureStore,
  collector: StreamCollector,
  part: LanguageModelV3StreamPart,
): void {
  if (part.type === "finish") {
    collector.sawFinish = true;
    collector.finishReason = part.finishReason.unified;
    collector.providerMetadata = part.providerMetadata;
    collector.usage = part.usage;
  } else if (part.type === "response-metadata") {
    collector.responseId = part.id;
    collector.responseModelId = part.modelId;
  } else if (part.type === "error") {
    collector.sawError = true;
  }

  try {
    const normalized = toJsonValue(part);
    const size = Buffer.byteLength(stringifyCanonicalJson(normalized));
    if (
      !collector.truncated &&
      collector.byteLength + size <= store.limits.maxAssetBytes
    ) {
      collector.parts.push(normalized);
      collector.byteLength += size;
    } else {
      collector.truncated = true;
    }
    if (part.type === "raw") {
      const raw = toJsonValue(part.rawValue);
      const rawSize = Buffer.byteLength(stringifyCanonicalJson(raw));
      if (
        !collector.rawTruncated &&
        collector.rawByteLength + rawSize <= store.limits.maxAssetBytes
      ) {
        collector.rawParts.push(raw);
        collector.rawByteLength += rawSize;
      } else {
        collector.rawTruncated = true;
      }
    }
  } catch {
    collector.truncated = true;
  }
}

function wrapCapturedStream(
  store: CaptureStore,
  capture: AttemptCapture,
  result: LanguageModelV3StreamResult,
  options: LanguageModelV3CallOptions,
  openFinalizers: Set<() => void>,
): LanguageModelV3StreamResult {
  const collector: StreamCollector = {
    parts: [],
    rawParts: [],
    byteLength: 0,
    rawByteLength: 0,
    truncated: false,
    rawTruncated: false,
    sawError: false,
    sawFinish: false,
  };
  const reader = result.stream.getReader();
  let finalized = false;
  const terminalLifecycle = (): {
    lifecycle: NativeRolloutAttemptLifecycle;
    outputState: "available" | "interrupted";
  } => {
    if (!collector.sawFinish || collector.sawError) {
      return { lifecycle: "partial", outputState: "interrupted" };
    }
    return {
      lifecycle: collector.finishReason === "length" ? "partial" : "completed",
      outputState: "available",
    };
  };
  const finalize = (
    lifecycle: NativeRolloutAttemptLifecycle,
    outputState: "available" | "truncated" | "interrupted",
  ) => {
    if (finalized) return;
    finalized = true;
    openFinalizers.delete(interrupt);
    const limitations: CaptureDiagnosticV1[] = [];
    if (collector.truncated) {
      limitations.push({
        code: "stream_limit",
        message: "the bounded collector omitted later stream parts",
        field: "boundary.output.normalized",
      });
    }
    if (collector.finishReason === "length") {
      limitations.push({
        code: "provider_length_limit",
        message: "the provider stopped generation at its output length limit",
        field: "boundary.output.normalized",
      });
    }
    safeEmitAttempt(store, capture, {
      lifecycle,
      nativeInput: result.request?.body,
      normalizedOutput: { parts: collector.parts },
      normalizedOutputState: collector.truncated ? "truncated" : outputState,
      nativeOutput:
        collector.rawParts.length > 0
          ? { chunks: collector.rawParts }
          : undefined,
      nativeOutputAbsent: options.includeRawChunks ? "omitted" : "unsupported",
      nativeOutputReason: options.includeRawChunks
        ? "the provider emitted no raw response chunks"
        : "raw provider chunks were not enabled for this existing call",
      providerMetadata: collector.providerMetadata,
      usage: collector.usage,
      providerRequestId: collector.responseId,
      effectiveModelId: collector.responseModelId,
      limitations,
    });
  };
  const interrupt = () => {
    const terminal = terminalLifecycle();
    finalize(terminal.lifecycle, terminal.outputState);
  };
  openFinalizers.add(interrupt);
  let stream: ReadableStream<LanguageModelV3StreamPart>;
  try {
    stream = new ReadableStream<LanguageModelV3StreamPart>({
      async pull(controller) {
        try {
          const next = await reader.read();
          if (next.done) {
            const terminal = terminalLifecycle();
            controller.close();
            finalize(terminal.lifecycle, terminal.outputState);
            return;
          }
          try {
            collectStreamPart(store, collector, next.value);
          } catch {
            collector.truncated = true;
          }
          controller.enqueue(next.value);
        } catch (error) {
          controller.error(error);
          finalize(
            collector.parts.length > 0 ? "partial" : "failed",
            "interrupted",
          );
        }
      },
      async cancel(reason) {
        if (collector.sawFinish) {
          const terminal = terminalLifecycle();
          finalize(terminal.lifecycle, terminal.outputState);
        } else {
          finalize("aborted", "interrupted");
        }
        await reader.cancel(reason);
      },
    });
  } catch (error) {
    openFinalizers.delete(interrupt);
    reader.releaseLock();
    throw error;
  }

  return { ...result, stream };
}

export function withNativeRolloutEvidenceModel(
  model: LanguageModelV3,
  defaultContext: NativeRolloutModelContext,
): LanguageModelV3 {
  const store = captureStore.getStore();
  if (!store?.enabled) return model;
  const activeStore = store;

  const pendingFailures = new Map<symbol, PendingFailure[]>();
  const openFinalizers = new Set<() => void>();
  const flush = () => {
    for (const failures of pendingFailures.values()) {
      for (const pending of failures) {
        safeEmitAttempt(activeStore, pending.capture, {
          lifecycle: "failed",
          nativeInput: pending.nativeInput,
          normalizedOutputState: "interrupted",
          nativeOutputAbsent: "omitted",
          nativeOutputReason:
            "the provider call failed before returning output",
        });
      }
    }
    pendingFailures.clear();
    for (const finalize of [...openFinalizers]) finalize();
  };
  activeStore.flushers.add(flush);

  const context = (): ResolvedOperationContext => {
    const override = operationStore.getStore();
    const session = sessionStore.getStore();
    return {
      model: {
        ...defaultContext,
        ...(override?.operationKind
          ? { operationKind: override.operationKind }
          : {}),
        ...(override?.sessionId ? { sessionId: override.sessionId } : {}),
        ...(session?.sessionId ? { sessionId: session.sessionId } : {}),
        ...(session?.parentSessionId && session.parentToolCallId
          ? {
              parentSessionId: session.parentSessionId,
              parentToolCallId: session.parentToolCallId,
            }
          : {}),
      },
      // Direct wrapper calls are independent by default. AI SDK retries share
      // the explicit outer operation scope installed at each Apex call site.
      invocation: override?.invocation ?? Symbol("unscoped-model-call"),
    };
  };

  const takePendingFailure = (
    invocation: symbol,
  ): PendingFailure | undefined => {
    const failures = pendingFailures.get(invocation);
    const pending = failures?.shift();
    if (failures?.length === 0) pendingFailures.delete(invocation);
    return pending;
  };

  const addPendingFailure = (invocation: symbol, failure: PendingFailure) => {
    const failures = pendingFailures.get(invocation) ?? [];
    failures.push(failure);
    pendingFailures.set(invocation, failures);
  };

  async function doGenerate(
    options: LanguageModelV3CallOptions,
  ): Promise<LanguageModelV3GenerateResult> {
    const current = context();
    const retry = takePendingFailure(current.invocation);
    if (retry) {
      safeEmitAttempt(activeStore, retry.capture, {
        lifecycle: "retried",
        nativeInput: retry.nativeInput,
        normalizedOutputState: "interrupted",
        nativeOutputAbsent: "omitted",
        nativeOutputReason: "the provider call failed before a retry",
      });
    }
    let capture: AttemptCapture;
    try {
      capture = beginAttempt(
        activeStore,
        current.model,
        model.provider,
        model.modelId,
        options,
        retry,
      );
    } catch {
      addDiagnostic(activeStore, {
        code: "capture_failure",
        message: "the passive collector could not start an attempt record",
      });
      return await model.doGenerate(options);
    }

    try {
      const result = await model.doGenerate(options);
      const lifecycle =
        result.finishReason.unified === "length" ? "partial" : "completed";
      safeEmitAttempt(activeStore, capture, {
        lifecycle,
        nativeInput: result.request?.body,
        normalizedOutput: {
          content: result.content,
          finishReason: result.finishReason,
          usage: result.usage,
          providerMetadata: result.providerMetadata,
          response: result.response
            ? {
                id: result.response.id,
                timestamp: result.response.timestamp,
                modelId: result.response.modelId,
              }
            : undefined,
        },
        nativeOutput: result.response?.body,
        providerMetadata: result.providerMetadata,
        usage: result.usage,
        providerRequestId: result.response?.id,
        effectiveModelId: result.response?.modelId,
        limitations:
          lifecycle === "partial"
            ? [
                {
                  code: "provider_length_limit",
                  message:
                    "the provider stopped generation at its output length limit",
                  field: "boundary.output.normalized",
                },
              ]
            : [],
      });
      return result;
    } catch (error) {
      addPendingFailure(current.invocation, {
        capture,
        nativeInput: errorRequestBody(error),
      });
      throw error;
    }
  }

  async function doStream(
    options: LanguageModelV3CallOptions,
  ): Promise<LanguageModelV3StreamResult> {
    const current = context();
    const retry = takePendingFailure(current.invocation);
    if (retry) {
      safeEmitAttempt(activeStore, retry.capture, {
        lifecycle: "retried",
        nativeInput: retry.nativeInput,
        normalizedOutputState: "interrupted",
        nativeOutputAbsent: "omitted",
        nativeOutputReason: "the provider call failed before a retry",
      });
    }
    let capture: AttemptCapture;
    try {
      capture = beginAttempt(
        activeStore,
        current.model,
        model.provider,
        model.modelId,
        options,
        retry,
      );
    } catch {
      addDiagnostic(activeStore, {
        code: "capture_failure",
        message: "the passive collector could not start an attempt record",
      });
      return await model.doStream(options);
    }

    let result: LanguageModelV3StreamResult;
    try {
      result = await model.doStream(options);
    } catch (error) {
      addPendingFailure(current.invocation, {
        capture,
        nativeInput: errorRequestBody(error),
      });
      throw error;
    }
    try {
      return wrapCapturedStream(
        activeStore,
        capture,
        result,
        options,
        openFinalizers,
      );
    } catch {
      addDiagnostic(activeStore, {
        code: "capture_failure",
        message: "the passive collector could not wrap the provider stream",
      });
      return result;
    }
  }

  return {
    specificationVersion: model.specificationVersion,
    provider: model.provider,
    modelId: model.modelId,
    supportedUrls: model.supportedUrls,
    doGenerate,
    doStream,
  };
}
