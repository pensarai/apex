import { describe, expect, it } from "vitest";
import { checkPermission, getPolicySummary } from "./permissionPolicy";
import type { ToolClassification } from "./types";

const classification: ToolClassification = {
  tier: 3,
  intent: "probing",
  reasoning: "Controlled probing",
  source: "rules",
  classifierMode: "rules",
  classifierVersion: "test",
};

describe("permissionPolicy", () => {
  it("auto-approves classifications at or below threshold", () => {
    expect(
      checkPermission(
        { requireApproval: true, autoApproveUpToTier: 3 },
        classification,
      ),
    ).toMatchObject({
      allowed: true,
      autoApproved: true,
    });
  });

  it("requires approval above threshold", () => {
    expect(
      checkPermission(
        { requireApproval: true, autoApproveUpToTier: 2 },
        classification,
      ),
    ).toMatchObject({
      allowed: true,
      autoApproved: false,
    });
  });

  it("summarizes threshold policy", () => {
    expect(
      getPolicySummary({ requireApproval: true, autoApproveUpToTier: 3 }),
    ).toContain("T1-T3");
  });
});
