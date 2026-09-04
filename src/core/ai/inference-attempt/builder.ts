import type { TransportUsageInput } from "./adapters";
import { adaptTransportUsage } from "./adapters";
import type {
  AttemptAttribution,
  AttemptEvidence,
  AttemptLifecycle,
  AttemptLineage,
  AttemptModelRef,
  AttemptOperationKind,
  InferenceAttempt,
} from "./envelope";
import {
  INFERENCE_ATTEMPT_SCHEMA,
  INFERENCE_ATTEMPT_VERSION,
} from "./envelope";
import { InferenceAttemptValidationError } from "./errors";
import type { AttemptIdentity } from "./identity";
import { allocateAttemptIdentity } from "./identity";
import type { AttemptTokens } from "./tokens";
import { finalizeTokens, UNKNOWN_TOKENS } from "./tokens";
import { parseInferenceAttempt } from "./validate";

export interface StartInferenceAttemptInput {
  operationKind: AttemptOperationKind;
  requested: AttemptModelRef;
  effective?: AttemptModelRef;
  attribution?: Omit<AttemptAttribution, "rootAttemptId"> & {
    rootAttemptId?: AttemptAttribution["rootAttemptId"];
  };
  lineage?: AttemptLineage;
  /** Root-minted key reused by `retry()` so the lineage can dedupe. */
  idempotencyKey?: AttemptIdentity["idempotencyKey"];
}

export interface AttemptUsageInput extends Partial<TransportUsageInput> {
  tokens?: AttemptTokens;
  evidence?: AttemptEvidence;
  effective?: AttemptModelRef;
}

export interface InferenceAttemptHandle extends AttemptIdentity {
  readonly started: InferenceAttempt;
  complete(input?: AttemptUsageInput): InferenceAttempt;
  fail(input?: AttemptUsageInput): InferenceAttempt;
  abort(input?: AttemptUsageInput): InferenceAttempt;
  partial(input?: AttemptUsageInput): InferenceAttempt;
  retried(input?: AttemptUsageInput): InferenceAttempt;
  /** Next physical try. Single-use; keeps this handle's idempotency key. */
  retry(): InferenceAttemptHandle;
}

export function startInferenceAttempt(
  input: StartInferenceAttemptInput,
): InferenceAttemptHandle {
  const identity = allocateAttemptIdentity({
    idempotencyKey: input.idempotencyKey,
  });
  const lineage: AttemptLineage = input.lineage ?? { sequence: 1 };
  const attribution: AttemptAttribution = {
    ...input.attribution,
    rootAttemptId: input.attribution?.rootAttemptId ?? identity.attemptId,
  };
  const requested = input.requested;
  const effective = input.effective ?? requested;

  const started = parseInferenceAttempt({
    schema: INFERENCE_ATTEMPT_SCHEMA,
    version: INFERENCE_ATTEMPT_VERSION,
    attemptId: identity.attemptId,
    idempotencyKey: identity.idempotencyKey,
    lifecycle: "started",
    operationKind: input.operationKind,
    lineage,
    attribution,
    requested,
    effective,
    tokens: UNKNOWN_TOKENS,
    evidence: {},
  });

  const settle = (
    lifecycle: Exclude<AttemptLifecycle, "started">,
    usage?: AttemptUsageInput,
  ): InferenceAttempt => {
    const { tokens, evidence } = resolveUsage(usage);
    return parseInferenceAttempt({
      schema: INFERENCE_ATTEMPT_SCHEMA,
      version: INFERENCE_ATTEMPT_VERSION,
      attemptId: identity.attemptId,
      idempotencyKey: identity.idempotencyKey,
      lifecycle,
      operationKind: input.operationKind,
      lineage,
      attribution,
      requested,
      effective: usage?.effective ?? effective,
      tokens,
      evidence,
    });
  };

  return {
    attemptId: identity.attemptId,
    idempotencyKey: identity.idempotencyKey,
    started,
    complete: (usage) => settle("completed", usage),
    fail: (usage) => settle("failed", usage),
    abort: (usage) => settle("aborted", usage),
    partial: (usage) => settle("partial", usage),
    retried: (usage) => settle("retried", usage),
    retry: (() => {
      let used = false;
      return () => {
        if (used) {
          throw new InferenceAttemptValidationError(
            "invalid-envelope",
            "retry() is single-use; chain from the returned handle",
          );
        }
        used = true;
        return startInferenceAttempt({
          operationKind: input.operationKind,
          requested,
          effective,
          attribution,
          idempotencyKey: identity.idempotencyKey,
          lineage: {
            sequence: lineage.sequence + 1,
            previousAttemptId: identity.attemptId,
          },
        });
      };
    })(),
  };
}

function resolveUsage(input?: AttemptUsageInput): {
  tokens: AttemptTokens;
  evidence: AttemptEvidence;
} {
  if (!input) {
    return { tokens: UNKNOWN_TOKENS, evidence: {} };
  }

  if (input.tokens) {
    return {
      tokens: finalizeTokens(input.tokens),
      evidence: input.evidence ?? {},
    };
  }

  if (input.transport) {
    const adapted = adaptTransportUsage({
      transport: input.transport,
      usage: input.usage,
      providerMetadata: input.providerMetadata,
      providerRequestId: input.providerRequestId,
      cacheTtlSeconds: input.cacheTtlSeconds,
      cacheBreakpoint: input.cacheBreakpoint,
    });
    return {
      tokens: adapted.tokens,
      evidence: { ...adapted.evidence, ...input.evidence },
    };
  }

  return {
    tokens: UNKNOWN_TOKENS,
    evidence: input.evidence ?? {},
  };
}
