import { describe, expect, it } from "vitest";
import { DeploymentPreflightArtifact } from "./engagementPreflight";

function capability(
  id: string,
  status: "available" | "unavailable" | "unknown",
  targetIds: string[] = [],
) {
  return {
    id,
    kind: "feature" as const,
    label: id,
    status,
    targetIds,
    evidence: status === "unknown" ? [] : [`GET /api/config: ${status}`],
    summary: `Capability is ${status}`,
    observedAt: "2026-09-19T12:00:00.000Z",
  };
}

describe("deployment preflight artifacts", () => {
  it("rejects unavailable facts without evidence", () => {
    expect(() =>
      DeploymentPreflightArtifact.parse({
        version: 1,
        status: "ready",
        contractHash: "contract-hash",
        targetIds: ["target-1"],
        capabilities: [
          {
            ...capability("llm-provider", "unavailable"),
            evidence: [],
          },
        ],
      }),
    ).toThrow("require evidence");
  });
});
