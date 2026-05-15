/**
 * Tests for the offsec prompt builders, focused on the
 * source-assessment hint paragraph added for whitebox engagements.
 *
 * Invariants:
 *   - Hint is empty when no codebase is configured (HTTP-only flows
 *     stay byte-identical to before).
 *   - Hint references the codebase path, the skill slug, the
 *     `whitebox-seed` memory tag, the scratchpad output convention,
 *     and the absolute scripts root.
 */
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
    // Should call out the output-discipline rule explicitly.
    expect(hint).toMatch(/Do not modify the target codebase/i);
  });
});
