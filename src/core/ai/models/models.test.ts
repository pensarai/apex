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

  it("pins latest-tier Claude (4.6 + 4.7) to 128K output", () => {
    // These four ship the 128K window; they MUST not fall through to the
    // generic `claude-opus-4-` / `claude-sonnet-4-` catch-alls (32K/64K)
    // and silently get clamped to a 4× smaller budget. Pensar-prefixed
    // IDs go through the same lookup, so cover them too.
    expect(getMaxOutputTokens("claude-opus-4-6-v1")).toBe(128_000);
    expect(getMaxOutputTokens("claude-opus-4-7")).toBe(128_000);
    expect(getMaxOutputTokens("claude-sonnet-4-6-v1")).toBe(128_000);
    expect(getMaxOutputTokens("claude-sonnet-4-7")).toBe(128_000);
    expect(getMaxOutputTokens("pensar:anthropic.claude-opus-4-7")).toBe(
      128_000,
    );
    expect(getMaxOutputTokens("pensar:anthropic.claude-opus-4-6-v1")).toBe(
      128_000,
    );
  });

  it("recognizes OpenAI family budgets", () => {
    // Bugbot flagged that the 4096 catch-all underestimated non-Claude
    // output budgets, making `fitMessagesToContext` overly permissive on
    // input. Pin the per-family values so future families (gpt-6, etc.)
    // can't silently inherit the small fallback again.
    expect(getMaxOutputTokens("gpt-5")).toBe(128_000);
    expect(getMaxOutputTokens("gpt-5-mini")).toBe(128_000);
    expect(getMaxOutputTokens("gpt-4.1")).toBe(32_000);
    expect(getMaxOutputTokens("gpt-4o")).toBe(16_000);
    expect(getMaxOutputTokens("gpt-4o-mini")).toBe(16_000);
    expect(getMaxOutputTokens("gpt-3.5-turbo")).toBe(4_096);
    expect(getMaxOutputTokens("o1")).toBe(100_000);
    expect(getMaxOutputTokens("o3")).toBe(100_000);
    expect(getMaxOutputTokens("o4-mini")).toBe(100_000);
    // `o3-mini` has only 128K context — `getMaxOutputTokens` clamps the
    // 100K pattern down to 50% of the window so input keeps headroom.
    expect(getMaxOutputTokens("o3-mini")).toBe(64_000);
  });

  it("recognizes Google Gemini family budgets", () => {
    expect(getMaxOutputTokens("gemini-2.5-pro")).toBe(65_000);
    expect(getMaxOutputTokens("gemini-2.5-flash")).toBe(65_000);
    expect(getMaxOutputTokens("gemini-2.0-flash")).toBe(8_192);
    expect(getMaxOutputTokens("gemini-3-pro-preview")).toBe(64_000);
    // `*-latest` aliases (1M context) must NOT inherit the 8K legacy
    // catch-all — they resolve to current top-tier Gemini at the
    // provider, so getMaxOutputTokens (now passed explicitly to
    // streamText) must match the 65K modern default.
    expect(getMaxOutputTokens("gemini-pro-latest")).toBe(65_000);
    expect(getMaxOutputTokens("gemini-flash-latest")).toBe(65_000);
    expect(getMaxOutputTokens("gemini-flash-lite-latest")).toBe(65_000);
  });

  it("falls back to a small default for genuinely unknown providers", () => {
    expect(getMaxOutputTokens("totally-unknown-model")).toBe(4_096);
  });
});
