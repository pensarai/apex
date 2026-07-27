import { describe, expect, it } from "vitest";
import { getHomeLayout } from "./home-layout";

describe("getHomeLayout", () => {
  it("keeps the primary prompt within narrow terminals", () => {
    expect(getHomeLayout(32, 16)).toMatchObject({
      inputWidth: 30,
      patternHeight: 2,
      showSubtitle: true,
      showWorkflowHints: false,
    });
  });

  it("shows only compact decoration on a standard 80x24 terminal", () => {
    expect(getHomeLayout(80, 24)).toMatchObject({
      inputWidth: 76,
      patternHeight: 3,
      showWorkflowHints: true,
      verticalGap: 2,
    });
  });

  it("caps prompt width and autocomplete height on large terminals", () => {
    expect(getHomeLayout(160, 60)).toMatchObject({
      inputWidth: 76,
      maxVisibleSuggestions: 8,
      patternHeight: 12,
    });
  });

  it("never returns negative dimensions", () => {
    expect(getHomeLayout(1, 1)).toMatchObject({
      inputWidth: 1,
      maxVisibleSuggestions: 2,
      patternHeight: 0,
    });
  });
});
