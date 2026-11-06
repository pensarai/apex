import { describe, expect, it } from "vitest";
import { FINDING_JUDGE_SYSTEM_PROMPT } from "./prompts";

describe("finding judge out-of-band rule", () => {
  it("accepts blind claims only on a cited callback hit, at capped confidence", () => {
    expect(FINDING_JUDGE_SYSTEM_PROMPT).toContain(
      "cites a callback hit (hitId, method, path, source IP, user agent, time) read with read_callback_hits",
    );
    expect(FINDING_JUDGE_SYSTEM_PROMPT).toContain(
      "confidence must stay below 0.7",
    );
    expect(FINDING_JUDGE_SYSTEM_PROMPT).toContain(
      "Reject an out-of-band claim with no cited hit, or one where the PoC requests the test domain directly.",
    );
  });
});
