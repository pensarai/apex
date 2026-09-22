import { describe, expect, it } from "vitest";
import {
  browserEngineForGoogleSignIn,
  GOOGLE_SIGNIN_PROMPT_GUIDANCE,
} from "./googleSignInPrompt";

describe("GOOGLE_SIGNIN_PROMPT_GUIDANCE", () => {
  it("teaches Google SSO rather than the target native form", () => {
    expect(GOOGLE_SIGNIN_PROMPT_GUIDANCE).toContain(
      "Do NOT fill the target's native username or password form",
    );
    expect(GOOGLE_SIGNIN_PROMPT_GUIDANCE).toContain("accounts.google.com");
    expect(GOOGLE_SIGNIN_PROMPT_GUIDANCE).toContain(
      'credentialField="password"',
    );
    expect(GOOGLE_SIGNIN_PROMPT_GUIDANCE).toContain("Google employee ID");
    expect(GOOGLE_SIGNIN_PROMPT_GUIDANCE).toContain(
      "this browser or app may not be secure",
    );
    expect(GOOGLE_SIGNIN_PROMPT_GUIDANCE).toContain("complete_authentication");
  });
});

describe("browserEngineForGoogleSignIn", () => {
  it("uses Chrome for Google Sign-In and Camoufox otherwise", () => {
    expect(browserEngineForGoogleSignIn(true)).toBe("chrome");
    expect(browserEngineForGoogleSignIn(false)).toBe("camoufox");
  });
});
