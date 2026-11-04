import { describe, expect, it } from "vitest";
import { classifyEntraSignInError } from "./entraSignInErrors";

describe("classifyEntraSignInError", () => {
  it.each([
    ["AADSTS53003", "Blocked by Conditional Access", "unknown"],
    [
      "AADSTS53000",
      "Blocked by Conditional Access: compliant device required",
      "unknown",
    ],
    [
      "AADSTS50076",
      "MFA required and no supported method was completed",
      "mfa",
    ],
    [
      "AADSTS50079",
      "MFA registration required; the account has no usable method",
      "mfa",
    ],
    [
      "AADSTS50053",
      "Account locked after too many sign-in attempts",
      "rate_limit",
    ],
    ["AADSTS50126", "Invalid username or password", "unknown"],
    ["AADSTS65001", "Application consent required", "oauth_consent"],
  ])("maps %s to a fixed reason", (input, reason, barrier) => {
    expect(classifyEntraSignInError(input)).toEqual({
      code: input,
      reason,
      barrier,
    });
  });

  it("normalizes a bare or lower-case code to the AADSTS form", () => {
    expect(classifyEntraSignInError("53003").code).toBe("AADSTS53003");
    expect(classifyEntraSignInError(" aadsts53003 ").code).toBe("AADSTS53003");
  });

  it("keeps an unknown code and marks it unrecognized", () => {
    expect(classifyEntraSignInError("AADSTS9999999")).toEqual({
      code: "AADSTS9999999",
      reason: "Unrecognized Entra sign-in error",
      barrier: "unknown",
    });
  });

  it("throws on anything that is not an AADSTS code", () => {
    expect(() => classifyEntraSignInError("blocked")).toThrow(
      "Not an Entra error code",
    );
  });
});
