import { describe, expect, it } from "vitest";
import {
  buildFastStrikeSystemPrompt,
  FAST_STRIKE_SYSTEM_PROMPT,
} from "./fastStrike";

describe("Fast Strike system prompt", () => {
  it("externalizes complex exploit chains into editable scripts", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "editable script in the session scratchpad directory",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "Never create a scratchpad/ directory inside the target repository",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("extending a working script");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "account for each viable primitive",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).not.toContain(
      "minimum number of commands",
    );
  });

  it("always terminates through the response tool after checking live primitives", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "whether the objective was met or every credible lead was genuinely exhausted",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "call the response tool with the correct solved value",
    );
  });

  it("keeps the native prompt as the default policy", () => {
    expect(buildFastStrikeSystemPrompt()).toBe(FAST_STRIKE_SYSTEM_PROMPT);
  });

  it("keeps the Strike loop but hands finding acceptance to the caller", () => {
    const prompt = buildFastStrikeSystemPrompt("external");
    expect(prompt).toContain("OBSERVE");
    expect(prompt).toContain("HYPOTHESIZE");
    expect(prompt).toContain("editable script");
    expect(prompt).toContain("submissionJson");
    expect(prompt).not.toContain("document_vulnerability");
    expect(prompt).not.toContain("validation judge");
  });
});
