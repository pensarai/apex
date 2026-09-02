export type InferenceAttemptValidationCode =
  | "invalid-token"
  | "inclusive-identity"
  | "invalid-envelope";

/** Thrown when usage or an envelope cannot be a valid attempt. */
export class InferenceAttemptValidationError extends Error {
  readonly code: InferenceAttemptValidationCode;

  constructor(code: InferenceAttemptValidationCode, message: string) {
    super(message);
    this.name = "InferenceAttemptValidationError";
    this.code = code;
  }
}
