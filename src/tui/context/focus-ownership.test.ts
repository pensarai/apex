import { describe, expect, it } from "vitest";

import { type FocusOwner, shouldRefocusPrompt } from "./focus-ownership";

function focusOwner(isDestroyed = false): FocusOwner {
  return { isDestroyed };
}

describe("shouldRefocusPrompt", () => {
  it("allows focus when no editor owns it", () => {
    expect(shouldRefocusPrompt(null, focusOwner())).toBe(true);
  });

  it("allows focus when the prompt already owns it", () => {
    const prompt = focusOwner();
    expect(shouldRefocusPrompt(prompt, prompt)).toBe(true);
  });

  it("allows focus when the previous editor was destroyed", () => {
    expect(shouldRefocusPrompt(focusOwner(true), focusOwner())).toBe(true);
  });

  it("preserves focus on another live editor", () => {
    expect(shouldRefocusPrompt(focusOwner(), focusOwner())).toBe(false);
  });
});
