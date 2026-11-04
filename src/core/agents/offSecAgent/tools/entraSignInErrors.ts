type EntraBarrierType = "mfa" | "oauth_consent" | "unknown";

interface EntraSignInError {
  reason: string;
  barrier: EntraBarrierType;
}

export const ENTRA_ERROR_CODE_PATTERN = /^(?:AADSTS)?(\d{5,7})$/i;

// https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
const ENTRA_SIGN_IN_ERRORS: Record<string, EntraSignInError> = {
  "50034": {
    reason: "Account does not exist in this tenant",
    barrier: "unknown",
  },
  "50053": {
    reason:
      "Account locked or sign-in blocked from this IP; the tenant's sign-in logs tell which",
    barrier: "unknown",
  },
  "50055": { reason: "Password expired", barrier: "unknown" },
  "50057": { reason: "Account disabled", barrier: "unknown" },
  "50072": {
    reason: "MFA registration required; the account has no usable method",
    barrier: "mfa",
  },
  "50074": {
    reason: "Strong authentication required and could not be completed",
    barrier: "mfa",
  },
  "50076": {
    reason: "MFA required and no supported method was completed",
    barrier: "mfa",
  },
  "50079": {
    reason: "MFA registration required; the account has no usable method",
    barrier: "mfa",
  },
  "50097": { reason: "Device authentication required", barrier: "unknown" },
  "50105": {
    reason: "Account is not assigned to the application",
    barrier: "unknown",
  },
  "50126": { reason: "Invalid username or password", barrier: "unknown" },
  "50158": {
    reason: "External security challenge was not satisfied",
    barrier: "mfa",
  },
  "53000": {
    reason: "Blocked by Conditional Access: compliant device required",
    barrier: "unknown",
  },
  "53001": {
    reason: "Blocked by Conditional Access: domain-joined device required",
    barrier: "unknown",
  },
  "53003": { reason: "Blocked by Conditional Access", barrier: "unknown" },
  "53004": {
    reason: "MFA registration blocked by Conditional Access",
    barrier: "mfa",
  },
  "65001": {
    reason: "Application consent required",
    barrier: "oauth_consent",
  },
  "90072": {
    reason: "Account is not a member or guest of the application's tenant",
    barrier: "unknown",
  },
  "500121": {
    reason: "MFA challenge failed, was denied, or timed out",
    barrier: "mfa",
  },
  "530032": {
    reason: "Blocked by Conditional Access security policy",
    barrier: "unknown",
  },
};

export function classifyEntraSignInError(errorCode: string): {
  code: string;
  reason: string;
  barrier: EntraBarrierType;
} {
  const match = ENTRA_ERROR_CODE_PATTERN.exec(errorCode.trim());
  if (!match) {
    throw new Error(`Not an Entra error code: ${errorCode}`);
  }
  const code = `AADSTS${match[1]}`;
  const known = ENTRA_SIGN_IN_ERRORS[match[1]];
  return known
    ? { code, ...known }
    : { code, reason: "Unrecognized Entra sign-in error", barrier: "unknown" };
}
