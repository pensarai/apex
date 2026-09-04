import { z } from "zod";
import type { AttemptID, IdempotencyKey } from "../../id/id";
import { isAttemptId, isIdempotencyKey } from "../../id/id";
import { InferenceAttemptValidationError } from "./errors";

export const INFERENCE_ATTEMPT_SCHEMA = "pensar.inference_attempt" as const;
export const INFERENCE_ATTEMPT_VERSION = 1 as const;

export const ATTEMPT_LIFECYCLES = [
  "started",
  "completed",
  "failed",
  "partial",
  "aborted",
  "retried",
] as const;
export type AttemptLifecycle = (typeof ATTEMPT_LIFECYCLES)[number];

export const ATTEMPT_OPERATION_KINDS = [
  "agent.stream",
  "structured.generate",
  "context.summarize",
  "tool.repair",
] as const;
export type AttemptOperationKind = (typeof ATTEMPT_OPERATION_KINDS)[number];

export const ATTEMPT_TRANSPORTS = [
  "anthropic-messages",
  "bedrock-converse",
  "pensar-anthropic-stream",
  "pensar-anthropic-rest",
  "openai-responses",
  "sdk-normalized",
] as const;
export type AttemptTransport = (typeof ATTEMPT_TRANSPORTS)[number];

export const CACHE_BREAKPOINTS = [
  "anthropic.cacheControl",
  "bedrock.cachePoint",
] as const;
export type CacheBreakpoint = (typeof CACHE_BREAKPOINTS)[number];

const attemptIdSchema = z.string().refine(isAttemptId, {
  message: "attemptId must start with atm_",
}) as z.ZodType<AttemptID>;

const idempotencyKeySchema = z.string().refine(isIdempotencyKey, {
  message: "idempotencyKey must start with idem_",
}) as z.ZodType<IdempotencyKey>;

const maybeTokenCountSchema = z.number().int().nonnegative().nullable();

const attemptTokensSchema = z.strictObject({
  inclusiveInput: maybeTokenCountSchema,
  uncachedInput: maybeTokenCountSchema,
  cacheRead: maybeTokenCountSchema,
  cacheWrite: maybeTokenCountSchema,
  output: maybeTokenCountSchema,
});

const modelRefSchema = z.strictObject({
  provider: z.string().min(1),
  modelId: z.string().min(1),
  transport: z.enum(ATTEMPT_TRANSPORTS).optional(),
});

const attributionSchema = z.strictObject({
  sessionId: z.string().min(1).optional(),
  runId: z.string().min(1).optional(),
  agentId: z.string().min(1).optional(),
  parentAttemptId: attemptIdSchema.optional(),
  rootAttemptId: attemptIdSchema,
});

const lineageSchema = z.strictObject({
  sequence: z.number().int().positive(),
  previousAttemptId: attemptIdSchema.optional(),
});

const evidenceSchema = z.strictObject({
  providerRequestId: z.string().min(1).optional(),
  cacheTtlSeconds: z.number().int().nonnegative().optional(),
  cacheBreakpoint: z.enum(CACHE_BREAKPOINTS).optional(),
});

export const InferenceAttemptSchema = z.strictObject({
  schema: z.literal(INFERENCE_ATTEMPT_SCHEMA),
  version: z.literal(INFERENCE_ATTEMPT_VERSION),
  attemptId: attemptIdSchema,
  idempotencyKey: idempotencyKeySchema,
  lifecycle: z.enum(ATTEMPT_LIFECYCLES),
  operationKind: z.enum(ATTEMPT_OPERATION_KINDS),
  lineage: lineageSchema,
  attribution: attributionSchema,
  requested: modelRefSchema,
  effective: modelRefSchema,
  tokens: attemptTokensSchema,
  evidence: evidenceSchema,
});

export type AttemptModelRef = z.infer<typeof modelRefSchema>;
export type AttemptAttribution = z.infer<typeof attributionSchema>;
export type AttemptLineage = z.infer<typeof lineageSchema>;
export type AttemptEvidence = z.infer<typeof evidenceSchema>;
export type InferenceAttempt = z.infer<typeof InferenceAttemptSchema>;

export function assertLineage(lineage: AttemptLineage): void {
  if (lineage.sequence === 1 && lineage.previousAttemptId !== undefined) {
    throw new InferenceAttemptValidationError(
      "invalid-envelope",
      "first attempt cannot name a previousAttemptId",
    );
  }
  if (lineage.sequence > 1 && lineage.previousAttemptId === undefined) {
    throw new InferenceAttemptValidationError(
      "invalid-envelope",
      "retry lineage requires previousAttemptId",
    );
  }
}
