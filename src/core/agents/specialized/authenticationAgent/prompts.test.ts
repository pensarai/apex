import { describe, expect, it } from "vitest";
import { AUTH_SUBAGENT_SYSTEM_PROMPT } from "./prompts";

describe("AUTH_SUBAGENT_SYSTEM_PROMPT", () => {
  it("distinguishes passwordless phone login from SMS MFA", () => {
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "`sms-passwordless`: `phoneNumber` is the login identifier",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "`sms-mfa`: fill username and password first",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "If submitting the password triggers the SMS code, reserve immediately before submitting",
    );
  });

  it("bounds busy-number retries without exposing a phone number", () => {
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "Never ask for, write, log, or pass a public phone number",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "Make at most two separate reservation attempts",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "sms_list_messages` with `sinceMs` and `claim=true",
    );
  });

  it("includes the Sign in with Google strategy", () => {
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "Do NOT fill the target's native username or password form",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain("accounts.google.com");
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain("Google employee ID");
  });
});
