import {
  type AttemptID,
  type IdempotencyKey,
  newAttemptId,
  newIdempotencyKey,
} from "../../id/id";

/** Opaque identity allocated before a provider request. */
export interface AttemptIdentity {
  attemptId: AttemptID;
  idempotencyKey: IdempotencyKey;
}

/**
 * Mint a fresh attempt id. Pass `idempotencyKey` to keep the same key
 * across a retry lineage; omit it to mint a new one at the root.
 */
export function allocateAttemptIdentity(opts?: {
  idempotencyKey?: IdempotencyKey;
}): AttemptIdentity {
  return {
    attemptId: newAttemptId(),
    idempotencyKey: opts?.idempotencyKey ?? newIdempotencyKey(),
  };
}
