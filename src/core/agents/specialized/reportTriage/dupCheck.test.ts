import { describe, expect, it } from "vitest";
import { FindingsRegistry } from "../../../findings/registry";
import { checkDuplicate, reportToFindingShape } from "./dupCheck";
import type { BountyReport } from "./types";

function makeReport(overrides: Partial<BountyReport> = {}): BountyReport {
  return {
    title: "Reflected XSS in search endpoint",
    reporterHandle: "h4xor",
    claimedSeverity: "HIGH",
    vulnerabilityClass: "Reflected XSS",
    affectedUrl: "https://example.com/search?q=test",
    affectedComponent: "search",
    attackerModel: "unauthenticated",
    description:
      "The /search endpoint reflects the q parameter into the HTML response without encoding.",
    impact: "Session hijack via JS in victim's browser.",
    pocSteps: [
      "Send GET /search?q=<script>alert(1)</script>",
      "Observe the payload reflected unencoded",
    ],
    pocCurl: "curl 'https://example.com/search?q=<script>alert(1)</script>'",
    references: [],
    ...overrides,
  };
}

describe("reportToFindingShape", () => {
  it("preserves title, endpoint, description, impact", () => {
    const f = reportToFindingShape(makeReport());
    expect(f.title).toBe("Reflected XSS in search endpoint");
    expect(f.endpoint).toBe("https://example.com/search?q=test");
    expect(f.description).toContain("reflects the q parameter");
    expect(f.impact).toContain("Session hijack");
  });

  it("collapses UNKNOWN / INFORMATIONAL claimedSeverity to LOW (not used by dedup)", () => {
    expect(
      reportToFindingShape(makeReport({ claimedSeverity: "UNKNOWN" })).severity,
    ).toBe("LOW");
    expect(
      reportToFindingShape(makeReport({ claimedSeverity: "INFORMATIONAL" }))
        .severity,
    ).toBe("LOW");
  });

  it("joins pocCurl + pocSteps into the evidence field", () => {
    const f = reportToFindingShape(makeReport());
    expect(f.evidence).toContain("curl 'https://example.com/search");
    expect(f.evidence).toContain("Observe the payload reflected unencoded");
  });
});

describe("checkDuplicate", () => {
  it("returns no duplicate against an empty registry", () => {
    const registry = new FindingsRegistry();
    const result = checkDuplicate({ report: makeReport(), registry });
    expect(result.duplicate).toBe(false);
    expect(result.matchType).toBe("none");
  });

  it("detects an exact endpoint + vuln-class duplicate", () => {
    const existing = reportToFindingShape(makeReport());
    const registry = FindingsRegistry.fromFindings([existing]);

    const result = checkDuplicate({ report: makeReport(), registry });
    expect(result.duplicate).toBe(true);
    expect(result.matchType).toBe("exact");
    expect(result.matchedTitle).toBe("Reflected XSS in search endpoint");
  });

  it("detects an application-wide duplicate (same title stem, different endpoint)", () => {
    const existing = reportToFindingShape(makeReport());
    const registry = FindingsRegistry.fromFindings([existing]);

    // Same vulnerability rediscovered on a different endpoint — stem matches.
    const result = checkDuplicate({
      report: makeReport({
        affectedUrl: "https://example.com/admin/search",
      }),
      registry,
    });
    expect(result.duplicate).toBe(true);
    expect(result.matchType).toBe("application-wide");
  });

  it("returns no duplicate when the vuln class differs", () => {
    const existing = reportToFindingShape(
      makeReport({
        title: "SQL injection in search endpoint",
        vulnerabilityClass: "SQL injection",
      }),
    );
    const registry = FindingsRegistry.fromFindings([existing]);

    const result = checkDuplicate({ report: makeReport(), registry });
    expect(result.duplicate).toBe(false);
  });
});
