import { describe, expect, it } from "vitest";
import fixture from "../../test-fixtures/agent-network-policy-v2.json";
import { isHostInScope } from "./targetScope";

describe("agent network policy fixture compatibility", () => {
  it("matches Console exact and wildcard host semantics", () => {
    const allowedHosts = fixture.destinations.map((destination) =>
      destination.wildcard ? `*.${destination.host}` : destination.host,
    );

    for (const testCase of fixture.scopeCases) {
      expect(
        isHostInScope(testCase.host, allowedHosts),
        testCase.host,
      ).toBe(testCase.allowed);
    }
  });

  it("keeps target, auxiliary, private, mapped, and mTLS fields distinct", () => {
    expect(
      fixture.destinations.find(
        (destination) => destination.sourceRef === "idp:platform-allowlist",
      )?.purpose,
    ).toBe("auxiliary");
    expect(
      fixture.destinations.find(
        (destination) => destination.host === "internal.corp.example",
      )?.route,
    ).toBe("customer-tailnet");
    expect(
      fixture.destinations.find(
        (destination) => destination.host === "mtls.example.test",
      )?.transport,
    ).toBe("tls");
    expect(fixture.hostnameMappings).toEqual([
      { hostname: "app.example.test", ip: "8.8.8.8" },
    ]);
    expect(fixture.rateLimit.aggregation).toBe("per-target-host");
  });
});
