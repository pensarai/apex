import { describe, expect, it } from "vitest";
import { buildSwarmSessionConfig, parseWebFlags } from "./command-flags";

describe("parseWebFlags", () => {
  it("auto-populates the target host and port for skipped-wizard swarm runs", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com:8080",
      "--swarm",
    ]);

    expect(flags.hosts).toEqual(["example.com"]);
    expect(flags.ports).toEqual([8080]);

    const params = buildSwarmSessionConfig(flags);

    expect(params.config.scopeConstraints).toMatchObject({
      allowedHosts: ["example.com"],
      allowedPorts: [8080],
    });
  });

  it("merges target-derived scope with explicit hosts and ports", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com:8080",
      "--swarm",
      "--hosts",
      "api.example.com",
      "--ports",
      "8443",
    ]);

    expect(flags.hosts).toEqual(["api.example.com", "example.com"]);
    expect(flags.ports).toEqual([8443, 8080]);
  });
});
