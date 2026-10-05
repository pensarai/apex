/** Display-safe constant: never embeds paths, ids, or provider details. */
export const RUN_PERSISTENCE_FAILED_MESSAGE =
  "Run context persistence failed; the canonical context for this run is unavailable.";

/**
 * Latched critical persistence failure. The message is constant and safe to
 * surface anywhere; the cause carries the store-specific details.
 */
export class RunPersistenceError extends Error {
  constructor(cause?: unknown) {
    super(RUN_PERSISTENCE_FAILED_MESSAGE, { cause });
    this.name = "RunPersistenceError";
  }
}
