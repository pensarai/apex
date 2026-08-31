import type { TransportUsageInput } from "./adapters";
import { adaptTransportUsage } from "./adapters";
import type {
  AttemptAttribution,
  AttemptEvidence,
  AttemptLifecycle,
  AttemptLineage,
  AttemptModelRef,
  AttemptOperationKind,
  ProviderAttemptEnvelope,
} from "./envelope";
import { PROVIDER_ATTEMPT_SCHEMA, PROVIDER_ATTEMPT_VERSION } from "./envelope";
import type { AttemptIdentity } from "./identity";
import { allocateAttemptIdentity } from "./identity";
import type { AttemptTokens } from "./tokens";
import { finalizeTokens, UNKNOWN_TOKENS } from "./tokens";
import { parseProviderAttemptEnvelope } from "./validate";

export interface StartProviderAttemptInput {
  operationKind: AttemptOperationKind;
  requested: AttemptModelRef;
  effective?: AttemptModelRef;
  attribution?: Omit<AttemptAttribution, "rootAttemptId"> & {
    rootAttemptId?: AttemptAttribution["rootAttemptId"];
  };
  lineage?: AttemptLineage;
}

export interface AttemptUsageInput extends Partial<TransportUsageInput> {
  tokens?: AttemptTokens;
  evidence?: AttemptEvidence;
  effective?: AttemptModelRef;
}

export interface ProviderAttemptHandle extends AttemptIdentity {
  readonly started: ProviderAttemptEnvelope;
  complete(input?: AttemptUsageInput): ProviderAttemptEnvelope;
  fail(input?: AttemptUsageInput): ProviderAttemptEnvelope;
  abort(input?: AttemptUsageInput): ProviderAttemptEnvelope;
  partial(input?: AttemptUsageInput): ProviderAttemptEnvelope;
  retried(input?: AttemptUsageInput): ProviderAttemptEnvelope;
  retry(): ProviderAttemptHandle;
}

export function startProviderAttempt(
  input: StartProviderAttemptInput,
): ProviderAttemptHandle {
  const identity = allocateAttemptIdentity();
  const lineage: AttemptLineage = input.lineage ?? { sequence: 1 };
  const attribution: AttemptAttribution = {
    ...input.attribution,
    rootAttemptId: input.attribution?.rootAttemptId ?? identity.attemptId,
  };
  const requested = input.requested;
  const effective = input.effective ?? requested;

  const started = parseProviderAttemptEnvelope({
    schema: PROVIDER_ATTEMPT_SCHEMA,
    version: PROVIDER_ATTEMPT_VERSION,
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
  ): ProviderAttemptEnvelope => {
    const { tokens, evidence } = resolveUsage(usage);
    return parseProviderAttemptEnvelope({
      schema: PROVIDER_ATTEMPT_SCHEMA,
      version: PROVIDER_ATTEMPT_VERSION,
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
    retry: () =>
      startProviderAttempt({
        operationKind: input.operationKind,
        requested,
        effective,
        attribution,
        lineage: {
          sequence: lineage.sequence + 1,
          previousAttemptId: identity.attemptId,
        },
      }),
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
