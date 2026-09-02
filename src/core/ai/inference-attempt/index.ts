/**
 * Versioned, money-free contract for one physical inference attempt.
 *
 * Token fields are finite non-negative integers when the provider reported
 * them and `null` when it did not. Missing is never coerced to zero here.
 *
 * Migration from completed-step callbacks (#1002):
 * - `projectAttemptUsage` maps envelope tokens onto
 *   `(inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens)` by
 *   treating `null` as `0`. If inclusive input is unknown, a known
 *   uncached total is reconstructed as the #1002 inclusive input
 *   (`uncached + zero-filled cache`) so omitted cache keys do not
 *   wipe a reported input count.
 * - `projectAttemptCacheMetrics` maps onto `CacheMetrics` only when a
 *   known cache field is `> 0`, matching `onCacheMetrics`.
 * - `onStepFinish` / `onCacheMetrics` / `onUsage` stay the live sinks.
 *   This module is not wired into `streamResponse` yet — that is #1013.
 *   Do not treat this module as a billing ledger.
 */

export type { AdaptedUsage, TransportUsageInput } from "./adapters";
export { adaptTransportUsage } from "./adapters";
export type {
  AttemptUsageInput,
  InferenceAttemptHandle,
  StartInferenceAttemptInput,
} from "./builder";
export { startInferenceAttempt } from "./builder";
export type {
  AttemptAttribution,
  AttemptEvidence,
  AttemptLifecycle,
  AttemptLineage,
  AttemptModelRef,
  AttemptOperationKind,
  AttemptTransport,
  CacheBreakpoint,
  InferenceAttempt,
} from "./envelope";
export {
  ATTEMPT_LIFECYCLES,
  ATTEMPT_OPERATION_KINDS,
  ATTEMPT_TRANSPORTS,
  CACHE_BREAKPOINTS,
  INFERENCE_ATTEMPT_SCHEMA,
  INFERENCE_ATTEMPT_VERSION,
  InferenceAttemptSchema,
} from "./envelope";

export type { InferenceAttemptValidationCode } from "./errors";
export { InferenceAttemptValidationError } from "./errors";
export type { AttemptIdentity } from "./identity";
export { allocateAttemptIdentity } from "./identity";
export type {
  ProjectedAttemptUsage,
  ProjectedCacheMetrics,
} from "./project";
export {
  projectAttemptCacheMetrics,
  projectAttemptUsage,
} from "./project";
export type { AttemptTokens, MaybeTokenCount } from "./tokens";
export { UNKNOWN_TOKEN_COUNT, UNKNOWN_TOKENS } from "./tokens";
export { parseInferenceAttempt } from "./validate";
