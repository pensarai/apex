import { describe, expect, it } from "vitest";
import { ENTRA_SIGNIN_PROMPT_GUIDANCE } from "./entraSignInPrompt";

describe("ENTRA_SIGNIN_PROMPT_GUIDANCE", () => {
  it("fills Microsoft sign-in secrets by credential reference", () => {
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain("login.microsoftonline.com");
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain(
      'credentialField="username"',
    );
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain(
      'credentialField="password"',
    );
  });

  it("switches push approval to a verification code or fails closed", () => {
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain("Use a verification code");
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain(
      "fail closed with an `mfa` barrier",
    );
  });

  it("never changes the account's sign-in methods", () => {
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain(
      "never add, remove, or change a sign-in method",
    );
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain(
      '"More information required" means setup is mandatory: that is a barrier',
    );
  });

  it("hands the AADSTS code to complete_authentication instead of a free-text reason", () => {
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain("`entraErrorCode`");
    expect(ENTRA_SIGNIN_PROMPT_GUIDANCE).toContain("do not reinterpret it");
  });
});
