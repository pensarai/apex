import { describe, expect, it } from "vitest";
import { mergeAuthCredentials } from "../core/agents/offSecAgent/tools/delegateAuth";
import { CredentialManager } from "../core/credentials";

describe("mergeAuthCredentials", () => {
  it("carries additional fields from the session credentials", () => {
    const merged = mergeAuthCredentials(
      {
        username: "admin",
        password: "pw",
        additionalFields: { TOTP_SEED: "JBSWY3DPEHPK3PXP" },
      },
      {},
    );
    expect(merged?.additionalFields).toEqual({ TOTP_SEED: "JBSWY3DPEHPK3PXP" });
  });

  it("prefers explicitly resolved additional fields", () => {
    const merged = mergeAuthCredentials(
      { username: "admin", password: "pw", additionalFields: { PIN: "1111" } },
      { username: "admin", additionalFields: { PIN: "2222" } },
    );
    expect(merged?.additionalFields).toEqual({ PIN: "2222" });
  });

  // The delegation path re-adds the merged credential to the manager, which
  // dedupes on every secret field. Dropping one here silently spawns a twin
  // credential that shares the login but is missing its extra secrets.
  it("re-adds onto the original credential instead of creating a twin", () => {
    const cm = new CredentialManager();
    const original = cm.addFromAuthCredentials({
      username: "admin",
      password: "pw",
      additionalFields: { TOTP_SEED: "JBSWY3DPEHPK3PXP" },
    });

    const stored = cm.resolve(original);
    const rebuilt = mergeAuthCredentials(undefined, {
      username: stored?.username,
      password: stored?.password,
      additionalFields: stored?.additionalFields,
    });
    expect(rebuilt).toBeDefined();

    expect(cm.addFromAuthCredentials(rebuilt ?? {})).toBe(original);
    expect(cm.size).toBe(1);
  });
});
