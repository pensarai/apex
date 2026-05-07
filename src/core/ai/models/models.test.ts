import { describe, it, expect } from "vitest";

import { AVAILABLE_MODELS, getMaxOutputTokens } from "./index";

describe("getMaxOutputTokens", () => {
  it("returns a positive value for every model in AVAILABLE_MODELS", () => {
    for (const model of AVAILABLE_MODELS) {
      const max = getMaxOutputTokens(model.id);
      expect(max, `model=${model.id}`).toBeGreaterThan(0);
    }
  });

  it("never returns a value ≥ contextLength (would zero out input budget)", () => {
    for (const model of AVAILABLE_MODELS) {
      if (!model.contextLength) continue;
      const max = getMaxOutputTokens(model.id);
      expect(
        max,
        `${model.id}: max_output (${max}) must be < context (${model.contextLength})`,
      ).toBeLessThan(model.contextLength);
    }
  });

  it("leaves ≥50K input headroom on every Anthropic model", () => {
    // Catches new Claude models silently inheriting the 4_096 default.
    const MIN = 50_000;
    for (const model of AVAILABLE_MODELS) {
      if (model.provider !== "anthropic" || !model.contextLength) continue;
      const headroom = model.contextLength - getMaxOutputTokens(model.id);
      expect(
        headroom,
        `${model.id}: headroom=${headroom}`,
      ).toBeGreaterThanOrEqual(MIN);
    }
  });

  it("recognizes Claude tier-specific budgets", () => {
    expect(getMaxOutputTokens("claude-sonnet-4-5-20250929")).toBe(64_000);
    expect(getMaxOutputTokens("claude-opus-4-5-20250101")).toBe(64_000);
    expect(getMaxOutputTokens("claude-haiku-4-5-20251001")).toBe(64_000);
    expect(getMaxOutputTokens("claude-opus-4-1-20250805")).toBe(32_000);
    expect(getMaxOutputTokens("claude-3-7-sonnet-20250219")).toBe(64_000);
    expect(getMaxOutputTokens("claude-3-5-haiku-20241022")).toBe(8_192);
  });

  it("falls back to a small default for unknown providers", () => {
    expect(getMaxOutputTokens("gpt-4o-mini")).toBe(4_096);
    expect(getMaxOutputTokens("gemini-2.5-pro")).toBe(4_096);
    expect(getMaxOutputTokens("totally-unknown-model")).toBe(4_096);
  });
});
