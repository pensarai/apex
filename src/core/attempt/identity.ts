import {
  type AttemptID,
  type IdempotencyKey,
  newAttemptId,
  newIdempotencyKey,
} from "../id/id";

/** Opaque identity allocated before a provider request. */
export interface AttemptIdentity {
  attemptId: AttemptID;
  idempotencyKey: IdempotencyKey;
}

/** Mint a fresh attempt id and idempotency key. Call before the request. */
export function allocateAttemptIdentity(): AttemptIdentity {
  return {
    attemptId: newAttemptId(),
    idempotencyKey: newIdempotencyKey(),
  };
}
