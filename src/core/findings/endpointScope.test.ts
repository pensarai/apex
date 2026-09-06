import { describe, expect, it } from "vitest";
import { endpointScopeDefaults } from "./endpointScope";

describe("endpoint scope recommendations", () => {
  it.each([
    "health_probe",
    "static_asset",
    "documentation",
    "robots_sitemap",
  ])("applies an evidence-backed exclusion for %s", (category) => {
    expect(
      endpointScopeDefaults({
        category,
        excludeByDefault: true,
        reason: "Confirmed public read-only response.",
      }),
    ).toEqual({
      excludedFromScan: true,
      exclusionReason: "Confirmed public read-only response.",
    });
  });

  it.each([
    ["health_probe", "Health handler fetches a user-supplied URL."],
    ["documentation", "Docs include tenant-specific data."],
    ["static_asset", "Download requires ownership checks."],
    ["other", "Metrics expose cross-tenant data."],
    ["other", "Cloud storage access pattern."],
    ["unknown", "Handler and response could not be inspected."],
  ])("keeps %s included when the analysis identifies a reason to test", (category, reason) => {
    expect(
      endpointScopeDefaults({ category, reason, excludeByDefault: false }),
    ).toEqual({ excludedFromScan: false, exclusionReason: null });
  });

  it("keeps old producers and unavailable analysis included", () => {
    expect(endpointScopeDefaults(undefined)).toEqual({
      excludedFromScan: false,
      exclusionReason: null,
    });
  });

  it.each([
    "other",
    "unknown",
    "metrics",
  ])("rejects automatic exclusion of %s", (category) => {
    expect(() =>
      endpointScopeDefaults({
        category,
        excludeByDefault: true,
        reason: "Low risk",
      }),
    ).toThrow();
  });

  it("requires evidence and a boolean at the boundary", () => {
    expect(() =>
      endpointScopeDefaults({
        category: "health_probe",
        excludeByDefault: true,
        reason: " ",
      }),
    ).toThrow();
    expect(() =>
      endpointScopeDefaults({
        category: "health_probe",
        excludeByDefault: "false",
        reason: "Probe",
      }),
    ).toThrow();
  });
});
