import { z } from "zod";
import type { AttemptID, IdempotencyKey } from "../../id/id";
import { isAttemptId, isIdempotencyKey } from "../../id/id";
import {
  ATTEMPT_OPERATION_KINDS,
  ATTEMPT_TRANSPORTS,
  type AttemptModelRef,
  type AttemptOperationKind,
  type AttemptTransport,
} from "../inference-attempt";

export const NATIVE_ROLLOUT_EVIDENCE_SCHEMA =
  "pensar.native_rollout_evidence" as const;
export const NATIVE_ROLLOUT_EVIDENCE_VERSION = 1 as const;
export const NATIVE_ROLLOUT_CAPTURE_REPORT_SCHEMA =
  "pensar.native_rollout_capture_report" as const;

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

class JsonValueValidationError extends Error {}

function cloneJsonValue(
  value: unknown,
  ancestors: WeakSet<object>,
  depth: number,
): JsonValue {
  if (depth > 64) {
    throw new JsonValueValidationError("JSON nesting exceeds 64 levels");
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new JsonValueValidationError("JSON contains a non-finite number");
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new JsonValueValidationError(
      `JSON contains unsupported ${typeof value}`,
    );
  }
  if (ancestors.has(value)) {
    throw new JsonValueValidationError("JSON contains a cycle");
  }

  const prototype = Object.getPrototypeOf(value);
  if (
    !Array.isArray(value) &&
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    throw new JsonValueValidationError("JSON contains a non-record object");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const cloned: JsonValue[] = [];
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) {
          throw new JsonValueValidationError(
            "JSON arrays cannot contain holes",
          );
        }
        cloned.push(cloneJsonValue(value[index], ancestors, depth + 1));
      }
      return cloned;
    }

    const cloned = Object.create(null) as Record<string, JsonValue>;
    for (const [key, entry] of Object.entries(value)) {
      cloned[key] = cloneJsonValue(entry, ancestors, depth + 1);
    }
    return cloned;
  } finally {
    ancestors.delete(value);
  }
}

export const JsonValueSchema: z.ZodType<JsonValue> = z
  .unknown()
  .transform((value, context) => {
    try {
      return cloneJsonValue(value, new WeakSet<object>(), 0);
    } catch (error) {
      context.addIssue({
        code: "custom",
        message:
          error instanceof JsonValueValidationError
            ? error.message
            : "invalid JSON value",
      });
      return z.NEVER;
    }
  });

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const CONTENT_REF_PATTERN = /^sha256:[a-f0-9]{64}$/;

export const ContentReferenceSchema = z.strictObject({
  ref: z.string().regex(CONTENT_REF_PATTERN),
  mediaType: z.string().min(1),
  byteLength: z.number().int().nonnegative(),
  representation: z.string().min(1),
});
export type ContentReferenceV1 = z.infer<typeof ContentReferenceSchema>;

export const ContentAddressedAssetSchema = z.strictObject({
  ref: z.string().regex(CONTENT_REF_PATTERN),
  sha256: z.string().regex(SHA256_PATTERN),
  mediaType: z.string().min(1),
  byteLength: z.number().int().nonnegative(),
  content: JsonValueSchema,
});
export type ContentAddressedAssetV1 = z.infer<
  typeof ContentAddressedAssetSchema
>;

export const NATIVE_EVIDENCE_UNAVAILABLE_STATES = [
  "unsupported",
  "omitted",
] as const;
export const NATIVE_EVIDENCE_PARTIAL_STATES = [
  "truncated",
  "interrupted",
] as const;
export const NATIVE_EVIDENCE_AVAILABILITY_STATES = [
  "available",
  ...NATIVE_EVIDENCE_UNAVAILABLE_STATES,
  ...NATIVE_EVIDENCE_PARTIAL_STATES,
] as const;

export type NativeEvidenceUnavailableState =
  (typeof NATIVE_EVIDENCE_UNAVAILABLE_STATES)[number];
export type NativeEvidencePartialState =
  (typeof NATIVE_EVIDENCE_PARTIAL_STATES)[number];

export type EvidenceAvailability<T> =
  | { state: "available"; value: T }
  | { state: NativeEvidenceUnavailableState; reason: string }
  | {
      state: NativeEvidencePartialState;
      reason: string;
      partial?: T;
      observed?: { sha256: string; byteLength: number };
    };

export function evidenceAvailabilitySchema<T extends z.ZodType>(value: T) {
  return z.discriminatedUnion("state", [
    z.strictObject({ state: z.literal("available"), value }),
    z.strictObject({
      state: z.enum(NATIVE_EVIDENCE_UNAVAILABLE_STATES),
      reason: z.string().min(1),
    }),
    z.strictObject({
      state: z.enum(NATIVE_EVIDENCE_PARTIAL_STATES),
      reason: z.string().min(1),
      partial: value.optional(),
      observed: z
        .strictObject({
          sha256: z.string().regex(SHA256_PATTERN),
          byteLength: z.number().int().nonnegative(),
        })
        .optional(),
    }),
  ]);
}

const contentAvailabilitySchema = evidenceAvailabilitySchema(
  ContentReferenceSchema,
);
const tokenIdsAvailabilitySchema = evidenceAvailabilitySchema(
  z.array(z.number().int().nonnegative()),
);
const logprobsAvailabilitySchema = evidenceAvailabilitySchema(
  z.array(z.number().finite()),
);
const tokenizerAvailabilitySchema = evidenceAvailabilitySchema(
  z.strictObject({
    name: z.string().min(1),
    version: z.string().min(1).optional(),
  }),
);

export const ProviderExtraSchema = z.strictObject({
  schema: z.string().min(1),
  version: z.number().int().positive(),
  provider: z.string().min(1),
  value: JsonValueSchema,
});
export type ProviderExtraV1 = z.infer<typeof ProviderExtraSchema>;

const providerExtraAvailabilitySchema =
  evidenceAvailabilitySchema(ProviderExtraSchema);

const attemptIdSchema = z.string().refine(isAttemptId, {
  message: "attemptId must start with atm_",
}) as z.ZodType<AttemptID>;
const idempotencyKeySchema = z.string().refine(isIdempotencyKey, {
  message: "idempotencyKey must start with idem_",
}) as z.ZodType<IdempotencyKey>;

export const NATIVE_ROLLOUT_ATTEMPT_LIFECYCLES = [
  "completed",
  "failed",
  "partial",
  "aborted",
  "retried",
] as const;
export type NativeRolloutAttemptLifecycle =
  (typeof NATIVE_ROLLOUT_ATTEMPT_LIFECYCLES)[number];

export const NativeRolloutAttemptSchema = z.strictObject({
  attemptId: attemptIdSchema,
  idempotencyKey: idempotencyKeySchema,
  sequence: z.number().int().positive(),
  rootAttemptId: attemptIdSchema,
  previousAttemptId: attemptIdSchema.optional(),
  lifecycle: z.enum(NATIVE_ROLLOUT_ATTEMPT_LIFECYCLES),
});
export type NativeRolloutAttemptV1 = z.infer<typeof NativeRolloutAttemptSchema>;

const modelRefSchema = z.strictObject({
  provider: z.string().min(1),
  modelId: z.string().min(1),
  transport: z.enum(ATTEMPT_TRANSPORTS).optional(),
});

export const NativeRolloutBoundarySchema = z.strictObject({
  input: z.strictObject({
    normalizedRef: ContentReferenceSchema,
    native: contentAvailabilitySchema,
  }),
  output: z.strictObject({
    normalized: contentAvailabilitySchema,
    native: contentAvailabilitySchema,
  }),
});
export type NativeRolloutBoundaryV1 = z.infer<
  typeof NativeRolloutBoundarySchema
>;

export const CaptureDiagnosticSchema = z.strictObject({
  code: z.string().min(1),
  message: z.string().min(1),
  field: z.string().min(1).optional(),
});
export type CaptureDiagnosticV1 = z.infer<typeof CaptureDiagnosticSchema>;

export const NativeRolloutEvidenceEnvelopeSchema = z.strictObject({
  schema: z.literal(NATIVE_ROLLOUT_EVIDENCE_SCHEMA),
  version: z.literal(NATIVE_ROLLOUT_EVIDENCE_VERSION),
  runId: z.string().min(1),
  sessionId: z.string().min(1).optional(),
  segmentId: z.string().min(1),
  turnId: z.string().min(1),
  turnIndex: z.number().int().positive(),
  operationKind: z.enum(ATTEMPT_OPERATION_KINDS),
  attempt: NativeRolloutAttemptSchema,
  requested: modelRefSchema,
  effective: modelRefSchema,
  boundary: NativeRolloutBoundarySchema,
  native: z.strictObject({
    promptTokenIds: tokenIdsAvailabilitySchema,
    completionTokenIds: tokenIdsAvailabilitySchema,
    logprobs: logprobsAvailabilitySchema,
    tokenizer: tokenizerAvailabilitySchema,
    extra: providerExtraAvailabilitySchema,
  }),
  assets: z.array(ContentAddressedAssetSchema),
  limitations: z.array(CaptureDiagnosticSchema),
});
export type NativeRolloutEvidenceEnvelopeV1 = z.infer<
  typeof NativeRolloutEvidenceEnvelopeSchema
>;

export const NATIVE_ROLLOUT_CAPTURE_STATES = [
  "disabled",
  "complete",
  "limited",
  "interrupted",
] as const;
export type NativeRolloutCaptureState =
  (typeof NATIVE_ROLLOUT_CAPTURE_STATES)[number];

export const NativeRolloutCaptureReportSchema = z.strictObject({
  schema: z.literal(NATIVE_ROLLOUT_CAPTURE_REPORT_SCHEMA),
  version: z.literal(NATIVE_ROLLOUT_EVIDENCE_VERSION),
  runId: z.string().min(1),
  state: z.enum(NATIVE_ROLLOUT_CAPTURE_STATES),
  attemptedRecords: z.number().int().nonnegative(),
  writtenRecords: z.number().int().nonnegative(),
  droppedRecords: z.number().int().nonnegative(),
  deliveryUnknownRecords: z.number().int().nonnegative(),
  diagnostics: z.array(CaptureDiagnosticSchema),
});
export type NativeRolloutCaptureReportV1 = z.infer<
  typeof NativeRolloutCaptureReportSchema
>;

export interface NativeRolloutEvidenceSink {
  write(
    envelope: NativeRolloutEvidenceEnvelopeV1,
    context: { signal: AbortSignal },
  ): void | Promise<void>;
}

export interface NativeRolloutCaptureLimits {
  maxAssetBytes: number;
  maxEnvelopeBytes: number;
  maxPendingRecords: number;
  maxDiagnostics: number;
  sinkTimeoutMs: number;
}

export interface NativeRolloutModelContext {
  requestedModelId: string;
  operationKind: AttemptOperationKind;
  sessionId?: string;
  transport?: AttemptTransport;
}

export type { AttemptModelRef, AttemptOperationKind, AttemptTransport };
