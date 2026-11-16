import { describe, expect, it } from "vitest";
import { CredentialManager } from "../../../credentials/manager";
import {
  buildCredentialsBlock,
  buildGeneralizedAttackSurfacePrompt,
} from "./generalizedPrompts";

describe("buildCredentialsBlock", () => {
  it("is empty without credentials", () => {
    expect(buildCredentialsBlock(undefined, undefined)).toBe("");
    expect(buildCredentialsBlock("", undefined)).toBe("");
  });

  it("lists credential references and how to log in, never the secret", () => {
    const manager = new CredentialManager();
    manager.add({
      id: "cred-1",
      username: "admin@acme.example",
      password: "hunter2-secret",
      loginUrl: "https://app.acme.example/login",
    });
    const block = buildCredentialsBlock(
      manager.formatForPrompt(),
      "Use the SSO button.",
    );
    expect(block).toContain("cred-1");
    expect(block).toContain("https://app.acme.example/login");
    expect(block).toContain("browser_fill");
    expect(block).toContain("Use the SSO button.");
    expect(block).not.toContain("hunter2-secret");
    expect(
      buildGeneralizedAttackSurfacePrompt(
        ["https://app.acme.example"],
        [],
        undefined,
        undefined,
        undefined,
        block,
      ),
    ).toContain("## Credentials");
  });
});
