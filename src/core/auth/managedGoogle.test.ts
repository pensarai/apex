import { describe, expect, it } from "vitest";
import { ManagedGoogleAuthError } from "./failures";
import {
  detectTypedFailure,
  extraScopesRequested,
  freezeModelToolsOnTransit,
} from "./managedGoogle";
import { filterMixedDomainState } from "./targetSession";
import { classifyOrigin, transitToolAllowed } from "./transit";

describe("managed Google transit", () => {
  it("classifies Google and issuer origins", () => {
    expect(classifyOrigin("https://accounts.google.com/signin")).toBe("google");
    expect(
      classifyOrigin("https://oidc.pensar.dev/authorize", {
        issuerUrl: "https://oidc.pensar.dev",
      }),
    ).toBe("issuer");
    expect(classifyOrigin("https://app.example.com/login")).toBe("target");
  });

  it("freezes evaluate and screenshots on transit origins", () => {
    expect(() =>
      freezeModelToolsOnTransit(
        "browser_evaluate",
        "https://accounts.google.com/",
      ),
    ).toThrow(ManagedGoogleAuthError);
    expect(
      transitToolAllowed("browser_evaluate", "https://accounts.google.com/"),
    ).toBe(false);
    expect(
      transitToolAllowed("browser_snapshot", "https://accounts.google.com/"),
    ).toBe(true);
  });

  it("rejects extra Google scopes", () => {
    expect(extraScopesRequested(["openid", "email", "profile"])).toBe(false);
    expect(
      extraScopesRequested([
        "openid",
        "https://www.googleapis.com/auth/gmail.readonly",
      ]),
    ).toBe(true);
  });

  it("detects typed Google failures", () => {
    const blocked = detectTypedFailure("This browser or app may not be secure");
    expect(blocked?.code).toBe("automation_block");
    const membership = detectTypedFailure("This account isn't a member");
    expect(membership?.code).toBe("target_membership");
  });

  it("filters mixed-domain browser state down to the target", () => {
    const filtered = filterMixedDomainState(
      {
        cookies: [
          {
            name: "app",
            value: "1",
            domain: "app.example.com",
            path: "/",
          },
          {
            name: "SID",
            value: "g",
            domain: "accounts.google.com",
            path: "/",
          },
        ],
        origins: [
          {
            origin: "https://app.example.com",
            localStorage: [{ name: "k", value: "v" }],
          },
        ],
      },
      { targetOrigin: "https://app.example.com" },
    );
    expect(filtered.cookies.map((cookie) => cookie.name)).toEqual(["app"]);
  });
});
