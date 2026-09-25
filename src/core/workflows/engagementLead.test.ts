import { describe, expect, it } from "vitest";
import { ENGAGEMENT_LEAD_SYSTEM_PROMPT } from "./engagementLead";

describe("engagement lead contract", () => {
  it("keeps direct testing, service coverage, delegation, and chaining under one owner", () => {
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).toContain("complete attack surface");
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).toContain("Work directly");
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).toContain("resume the same worker");
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).toContain("every objective");
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).toContain("crown-jewel impact");
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).toContain("finding judge");
    expect(ENGAGEMENT_LEAD_SYSTEM_PROMPT).not.toContain("Argus");
  });
});
