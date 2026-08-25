import { describe, expect, it } from "vitest";
import { findSelectedModelIndex } from "./model-navigation";

describe("findSelectedModelIndex", () => {
  it("focuses the selected recent model instead of the first recent model", () => {
    expect(
      findSelectedModelIndex(
        [
          { type: "recent-model", model: { id: "model-a" } },
          { type: "recent-model", model: { id: "model-b" } },
          { type: "provider" },
          { type: "model", model: { id: "model-b" } },
        ],
        "model-b",
      ),
    ).toBe(1);
  });

  it("finds the selected model outside recent history", () => {
    expect(
      findSelectedModelIndex(
        [
          { type: "recent-model", model: { id: "model-a" } },
          { type: "provider" },
          { type: "model", model: { id: "model-b" } },
        ],
        "model-b",
      ),
    ).toBe(2);
  });

  it("returns -1 when the selected model is not visible", () => {
    expect(
      findSelectedModelIndex(
        [
          { type: "recent-model", model: { id: "model-a" } },
          { type: "provider" },
        ],
        "model-b",
      ),
    ).toBe(-1);
  });
});
