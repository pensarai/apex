import { describe, expect, it } from "vitest";
import {
  FINDING_JUDGE_SYSTEM_PROMPT,
  findingJudgeSystemPrompt,
} from "./prompts";

describe("finding judge out-of-band rule", () => {
  it("accepts blind claims only on a cited callback hit, at capped confidence, when the host supplies callback domains", () => {
    const prompt = findingJudgeSystemPrompt(["probe.cb.example.net"]);
    expect(prompt).toContain(
      "cites a callback hit (hitId, method, path, source IP, user agent, time) read with read_callback_hits",
    );
    expect(prompt).toContain("confidence must stay below 0.7");
    expect(prompt).toContain(
      "Reject an out-of-band claim with no cited hit, or one where the PoC requests the test domain directly.",
    );
    // The rule sits with the other evidence-type rules, ahead of email.
    expect(prompt.indexOf("- Out-of-band")).toBeLessThan(
      prompt.indexOf("- Email/HTML injection:"),
    );
  });

  it("leaves the judge prompt unchanged without callback domains", () => {
    const prompt = findingJudgeSystemPrompt([]);
    expect(prompt).toBe(FINDING_JUDGE_SYSTEM_PROMPT);
    expect(prompt).not.toContain("read_callback_hits");
  });
});
