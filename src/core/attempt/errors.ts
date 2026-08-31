export type ProviderAttemptValidationCode =
  | "invalid-token"
  | "inclusive-identity"
  | "invalid-envelope";

/** Thrown when usage or an envelope cannot be a valid attempt. */
export class ProviderAttemptValidationError extends Error {
  readonly code: ProviderAttemptValidationCode;

  constructor(code: ProviderAttemptValidationCode, message: string) {
    super(message);
    this.name = "ProviderAttemptValidationError";
    this.code = code;
  }
}
