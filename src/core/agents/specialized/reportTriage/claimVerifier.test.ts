import { describe, expect, it } from "vitest";
import { buildMaterialClaims } from "./claimVerifier";
import type { BountyReport } from "./types";

const REPORT: BountyReport = {
  title: "Open redirect in login",
  claimedSeverity: "MEDIUM",
  vulnerabilityClass: "Open Redirect",
  affectedUrl: "https://example.com/login",
  affectedComponent: "next parameter",
  attackerModel: "unauthenticated user",
  description: "The next parameter redirects users to an attacker URL.",
  impact: "Phishing via trusted redirector",
  pocSteps: ["Visit /login?next=https://evil.example", "Observe redirect"],
  references: [],
};

describe("buildMaterialClaims", () => {
  it("extracts required material claims from a report", () => {
    const claims = buildMaterialClaims(REPORT);

    expect(claims.map((claim) => claim.id)).toEqual([
      "vulnerability-class",
      "affected-location",
      "attacker-model",
      "security-impact",
      "claimed-impact-details",
      "affected-component",
      "poc-steps",
    ]);
    expect(
      claims
        .filter((claim) =>
          [
            "vulnerability-class",
            "affected-location",
            "attacker-model",
            "security-impact",
          ].includes(claim.id),
        )
        .every((claim) => claim.required),
    ).toBe(true);
    expect(
      claims
        .filter((claim) =>
          [
            "claimed-impact-details",
            "affected-component",
            "poc-steps",
          ].includes(claim.id),
        )
        .every((claim) => !claim.required),
    ).toBe(true);
    expect(
      claims.find((claim) => claim.id === "security-impact")?.claim,
    ).toContain("Phishing");
  });
});
