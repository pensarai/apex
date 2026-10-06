export const MANAGED_GOOGLE_FAILURES = [
  "automation_block",
  "admin_policy",
  "extra_scopes",
  "target_membership",
  "callback_failure",
  "verification_failure",
  "identity_not_ready",
] as const;

export type ManagedGoogleFailure = (typeof MANAGED_GOOGLE_FAILURES)[number];

export class ManagedGoogleAuthError extends Error {
  readonly code: ManagedGoogleFailure;

  constructor(code: ManagedGoogleFailure, message: string) {
    super(message);
    this.name = "ManagedGoogleAuthError";
    this.code = code;
  }
}

export function isManagedGoogleAuthError(
  error: unknown,
): error is ManagedGoogleAuthError {
  return error instanceof ManagedGoogleAuthError;
}
