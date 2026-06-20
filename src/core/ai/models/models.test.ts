import { describe, expect, it } from "vitest";

import {
  DEFAULT_OPENAI_REASONING_EFFORT,
  modelSupportsOpenAIReasoning,
  normalizeOpenAIReasoningEffort,
} from "../ai";
import {
  AVAILABLE_MODELS,
  getMaxOutputTokens,
  getModelInfo,
  prefersSequentialToolCalls,
} from "./index";

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

  it("pins MiniMax M3 to the top-tier Opus output budget", () => {
    // M3 matches our flagship Opus 128K output rather than its advertised
    // 512K max, leaving input headroom within the 512Ki context window.
    expect(getMaxOutputTokens("minimax/minimax-m3")).toBe(128_000);
  });

  it("recognizes GLM 5.2's 131.1K max-output window", () => {
    expect(getMaxOutputTokens("z-ai/glm-5.2")).toBe(131_072);
  });

  it("recognizes Claude tier-specific budgets", () => {
    expect(getMaxOutputTokens("claude-sonnet-4-5-20250929")).toBe(64_000);
    expect(getMaxOutputTokens("claude-opus-4-5-20250101")).toBe(64_000);
    expect(getMaxOutputTokens("claude-haiku-4-5-20251001")).toBe(64_000);
    expect(getMaxOutputTokens("claude-opus-4-1-20250805")).toBe(32_000);
    expect(getMaxOutputTokens("claude-3-7-sonnet-20250219")).toBe(64_000);
    expect(getMaxOutputTokens("claude-3-5-haiku-20241022")).toBe(8_192);
  });

  it("pins latest-tier Claude (4.6 + 4.7 + 4.8) to 128K output", () => {
    // These ship the 128K window; they MUST not fall through to the
    // generic `claude-opus-4-` / `claude-sonnet-4-` catch-alls (32K/64K)
    // and silently get clamped to a 4× smaller budget. Pensar-prefixed
    // IDs go through the same lookup, so cover them too.
    expect(getMaxOutputTokens("claude-opus-4-6-v1")).toBe(128_000);
    expect(getMaxOutputTokens("claude-opus-4-7")).toBe(128_000);
    expect(getMaxOutputTokens("claude-opus-4-8")).toBe(128_000);
    expect(getMaxOutputTokens("claude-sonnet-4-6-v1")).toBe(128_000);
    expect(getMaxOutputTokens("claude-sonnet-4-7")).toBe(128_000);
    expect(getMaxOutputTokens("claude-sonnet-4-8")).toBe(128_000);
    expect(getMaxOutputTokens("pensar:anthropic.claude-opus-4-8")).toBe(
      128_000,
    );
    expect(getMaxOutputTokens("pensar:anthropic.claude-opus-4-7")).toBe(
      128_000,
    );
    expect(getMaxOutputTokens("pensar:anthropic.claude-opus-4-6-v1")).toBe(
      128_000,
    );
  });

  it("matches OpenRouter Claude IDs that use dots instead of dashes", () => {
    // OpenRouter uses dots in version numbers (anthropic/claude-opus-4.6)
    // while native Anthropic uses dashes (claude-opus-4-6). Both must resolve
    // to the same budget — not fall through to the 4,096 default.
    expect(getMaxOutputTokens("anthropic/claude-opus-4.6")).toBe(128_000);
    expect(getMaxOutputTokens("anthropic/claude-sonnet-4.5")).toBe(64_000);
    expect(getMaxOutputTokens("anthropic/claude-opus-4.5")).toBe(64_000);
    expect(getMaxOutputTokens("anthropic/claude-haiku-4.5")).toBe(64_000);
    expect(getMaxOutputTokens("anthropic/claude-3.5-sonnet")).toBe(8_192);
  });

  it("matches bare generation-4 Claude IDs (OpenRouter, no tier suffix)", () => {
    // OpenRouter ships `anthropic/claude-sonnet-4` and
    // `anthropic/claude-opus-4` — IDs with NO tier-revision suffix.
    // Anthropic-canonical IDs always carry a date / `-v1` suffix so they
    // hit the dashed `claude-{tier}-4-` branches; the bare-gen-4 variants
    // would otherwise fall through to the 4,096 catch-all (and now that
    // `getMaxOutputTokens` is passed explicitly to `streamText`, get
    // hard-capped at 4K instead of the documented per-tier limit).
    expect(getMaxOutputTokens("anthropic/claude-sonnet-4")).toBe(64_000);
    expect(getMaxOutputTokens("anthropic/claude-opus-4")).toBe(32_000);
    // Negative-lookahead must NOT misfire on the dashed canonical
    // forms: `claude-sonnet-4-5` still resolves via the explicit branch.
    expect(getMaxOutputTokens("anthropic/claude-sonnet-4-5")).toBe(64_000);
    expect(getMaxOutputTokens("anthropic/claude-opus-4-1")).toBe(32_000);
  });

  it("recognizes OpenAI family budgets", () => {
    // Bugbot flagged that the 4096 catch-all underestimated non-Claude
    // output budgets, making `fitMessagesToContext` overly permissive on
    // input. Pin the per-family values so future families (gpt-6, etc.)
    // can't silently inherit the small fallback again.
    expect(getMaxOutputTokens("gpt-5")).toBe(128_000);
    expect(getMaxOutputTokens("gpt-5.5")).toBe(128_000);
    expect(getMaxOutputTokens("gpt-5.5-2026-04-23")).toBe(128_000);
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

  it("pins GPT-5.5 context metadata", () => {
    expect(getModelInfo("gpt-5.5").contextLength).toBe(1_050_000);
    expect(getModelInfo("gpt-5.5-2026-04-23").contextLength).toBe(1_050_000);
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

describe("prefersSequentialToolCalls", () => {
  it("is true for DeepSeek models (Bedrock mis-parses parallel tool calls)", () => {
    expect(prefersSequentialToolCalls("deepseek.v3-v1:0")).toBe(true);
    expect(prefersSequentialToolCalls("us.deepseek.r1-v1:0")).toBe(true);
    expect(prefersSequentialToolCalls("deepseek/deepseek-chat")).toBe(true);
  });

  it("is false for models that parse parallel tool calls natively", () => {
    expect(prefersSequentialToolCalls("qwen.qwen3-coder-480b-a35b-v1:0")).toBe(
      false,
    );
    expect(
      prefersSequentialToolCalls(
        "global.anthropic.claude-haiku-4-5-20251001-v1:0",
      ),
    ).toBe(false);
    expect(prefersSequentialToolCalls("us.anthropic.claude-opus-4-6-v1")).toBe(
      false,
    );
    // Don't false-positive on substrings of unrelated ids.
    expect(prefersSequentialToolCalls("some-deepseeker-model")).toBe(false);
  });

  it("registers DeepSeek V3.1 and Qwen3 Coder 480B as bedrock models", () => {
    expect(getModelInfo("deepseek.v3-v1:0").provider).toBe("bedrock");
    expect(getModelInfo("qwen.qwen3-coder-480b-a35b-v1:0").provider).toBe(
      "bedrock",
    );
  });
});

describe("OpenAI reasoning effort support", () => {
  it("supports GPT-5.5 and o-series reasoning models", () => {
    expect(modelSupportsOpenAIReasoning("gpt-5.5")).toBe(true);
    expect(modelSupportsOpenAIReasoning("gpt-5.5-2026-04-23")).toBe(true);
    expect(modelSupportsOpenAIReasoning("o3-mini")).toBe(true);
  });

  it("does not apply reasoning effort to unsupported GPT-5 variants", () => {
    expect(modelSupportsOpenAIReasoning("gpt-5-nano")).toBe(false);
    expect(modelSupportsOpenAIReasoning("gpt-5.1-codex-mini")).toBe(false);
    expect(modelSupportsOpenAIReasoning("gpt-5.1-codex-max")).toBe(false);
    expect(modelSupportsOpenAIReasoning("gpt-5.3-codex")).toBe(false);
    expect(normalizeOpenAIReasoningEffort("gpt-5-nano")).toBeUndefined();
  });

  it("defaults only supported reasoning models to medium", () => {
    expect(normalizeOpenAIReasoningEffort("gpt-5.5")).toBe(
      DEFAULT_OPENAI_REASONING_EFFORT,
    );
  });
});
