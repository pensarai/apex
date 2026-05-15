import { describe, expect, it } from "vitest";
import { whiteboxScriptsRoot } from "../../skills/builtins";
import { buildSourceAssessmentHint } from "./prompt";

describe("buildSourceAssessmentHint", () => {
  it("returns an empty string when no codebasePath is set", () => {
    expect(buildSourceAssessmentHint({})).toBe("");
    expect(buildSourceAssessmentHint({ config: {} })).toBe("");
  });

  it("emits a hint referencing the skill, memory tag, and scripts root", () => {
    const hint = buildSourceAssessmentHint({
      config: { codebasePath: "/repos/target" },
    });
    expect(hint).toContain("/repos/target");
    expect(hint).toContain("whitebox-assessment");
    expect(hint).toContain("whitebox-seed");
    expect(hint).toContain("scratchpad/whitebox");
    expect(hint).toContain(whiteboxScriptsRoot());
    expect(hint).toMatch(/Do not modify the target codebase/i);
  });
});
