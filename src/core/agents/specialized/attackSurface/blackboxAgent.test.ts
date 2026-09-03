import { describe, expect, it } from "vitest";
import { CredentialManager } from "../../../credentials";
import type { SessionInfo } from "../../../session";
import { buildBlackboxPrompt } from "./blackboxAgent";

describe("buildBlackboxPrompt", () => {
  it("guides SMS MFA without exposing the shared number", () => {
    const credentialManager = new CredentialManager();
    credentialManager.add({
      username: "tester",
      password: "secret",
      loginUrl: "https://example.com/login",
      additionalFields: {
        authMethod: "sms-mfa",
        phoneNumber: "stage-managed-number",
      },
    });

    const prompt = buildBlackboxPrompt("https://example.com", {
      id: "session-1",
      rootPath: "/tmp/apex-blackbox-prompt",
      config: {},
      credentialManager,
    } as SessionInfo);

    expect(prompt).toContain("Authentication method: sms-mfa");
    expect(prompt).toContain("`sms-mfa`: fill username and password first");
    expect(prompt).toContain("Make at most two separate reservation attempts");
    expect(prompt).not.toContain("stage-managed-number");
  });
});
