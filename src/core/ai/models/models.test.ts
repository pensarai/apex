import { describe, expect, it } from "vitest";

import {
  DEFAULT_OPENAI_REASONING_EFFORT,
  getOpenAIReasoningEfforts,
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

  it("registers Laguna S 2.1 with its OpenRouter limits", () => {
    expect(getModelInfo("poolside/laguna-s-2.1")).toMatchObject({
      name: "Laguna S 2.1",
      provider: "openrouter",
      contextLength: 1_048_576,
    });
    expect(getMaxOutputTokens("poolside/laguna-s-2.1")).toBe(131_072);
  });

  it("registers Nemotron 3 Ultra with its OpenRouter limits", () => {
    expect(getModelInfo("nvidia/nemotron-3-ultra-550b-a55b")).toMatchObject({
      name: "Nemotron 3 Ultra 550B A55B",
      provider: "openrouter",
      contextLength: 262_144,
    });
    expect(getMaxOutputTokens("nvidia/nemotron-3-ultra-550b-a55b")).toBe(
      16_384,
    );
  });

  it("registers GLM 5.3 with its OpenRouter limits", () => {
    expect(getModelInfo("z-ai/glm-5.3")).toMatchObject({
      name: "GLM 5.3",
      provider: "openrouter",
      contextLength: 1_048_576,
    });
    expect(getMaxOutputTokens("z-ai/glm-5.3")).toBe(131_072);
  });

  it("recognizes GLM 5 / 5.2's 131.1K max-output window", () => {
    expect(getMaxOutputTokens("z-ai/glm-5.2")).toBe(131_072);
    expect(getMaxOutputTokens("zai.glm-5")).toBe(131_072);
  });

  it("registers DeepSeek V4.1 Flash with its OpenRouter limits", () => {
    expect(getModelInfo("deepseek/deepseek-v4.1-flash")).toMatchObject({
      name: "DeepSeek V4.1 Flash",
      provider: "openrouter",
      contextLength: 1_048_576,
    });
    expect(getMaxOutputTokens("deepseek/deepseek-v4.1-flash")).toBe(384_000);
  });

  it("recognizes the new Bedrock DeepSeek / Qwen output budgets", () => {
    // These three were silently inheriting the 4,096 catch-all, capping
    // replies far below each model's documented Bedrock limit.
    expect(getMaxOutputTokens("deepseek.v3-v1:0")).toBe(8_192);
    expect(getMaxOutputTokens("us.deepseek.r1-v1:0")).toBe(8_192);
    expect(getMaxOutputTokens("qwen.qwen3-coder-480b-a35b-v1:0")).toBe(16_000);
  });

  it("recognizes Claude tier-specific budgets", () => {
    expect(getMaxOutputTokens("claude-haiku-5-5")).toBe(128_000);
    expect(getMaxOutputTokens("global.anthropic.claude-haiku-5-5")).toBe(
      128_000,
    );
    expect(getMaxOutputTokens("anthropic/claude-haiku-5.5")).toBe(128_000);
    expect(getMaxOutputTokens("claude-sonnet-4-5-20250929")).toBe(64_000);
    expect(getMaxOutputTokens("claude-opus-4-5-20250101")).toBe(64_000);
    expect(getMaxOutputTokens("claude-haiku-4-5-20251001")).toBe(64_000);
    expect(getMaxOutputTokens("claude-opus-4-1-20250805")).toBe(32_000);
    expect(getMaxOutputTokens("claude-3-7-sonnet-20250219")).toBe(64_000);
    expect(getMaxOutputTokens("claude-3-5-haiku-20241022")).toBe(8_192);
  });

  it("registers Claude Haiku 5.5 across Anthropic, Bedrock, and OpenRouter", () => {
    expect(getModelInfo("claude-haiku-5-5")).toMatchObject({
      name: "Claude Haiku 5.5",
      provider: "anthropic",
      contextLength: 1_000_000,
    });
    expect(getModelInfo("global.anthropic.claude-haiku-5-5")).toMatchObject({
      name: "Claude Haiku 5.5 (Global)",
      provider: "bedrock",
      contextLength: 1_000_000,
    });
    expect(getModelInfo("anthropic/claude-haiku-5.5")).toMatchObject({
      name: "Claude Haiku 5.5",
      provider: "openrouter",
      contextLength: 1_000_000,
    });
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

  it("registers the GPT-6.1 family with its 1.05M context window", () => {
    for (const id of ["gpt-6.1-sol", "gpt-6.1-terra"]) {
      expect(getModelInfo(id)).toMatchObject({
        provider: "openai",
        contextLength: 1_050_000,
      });
      expect(getModelInfo(id).provider).not.toBe("local");
    }
    expect(getModelInfo("concentrate:gpt-6.1-terra")).toMatchObject({
      name: "GPT 6.1 Terra",
      provider: "concentrate",
      contextLength: 1_050_000,
    });
    expect(getModelInfo("concentrate:kimi-k3-1-pro")).toMatchObject({
      name: "Kimi K3.1 Pro",
      provider: "concentrate",
      contextLength: 1_048_576,
    });
  });

  it("registers the GPT-5.6 family with its 1.05M context window", () => {
    for (const id of ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"]) {
      expect(getModelInfo(id)).toMatchObject({
        provider: "openai",
        contextLength: 1_050_000,
      });
    }
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

  it("registers DeepSeek V3.1, Qwen3 Coder 480B, and GLM 5 as bedrock models", () => {
    expect(getModelInfo("deepseek.v3-v1:0").provider).toBe("bedrock");
    expect(getModelInfo("qwen.qwen3-coder-480b-a35b-v1:0").provider).toBe(
      "bedrock",
    );
    expect(getModelInfo("zai.glm-5").provider).toBe("bedrock");
  });

  it("does not force GLM 5 / Qwen into sequential tool calls (they parse parallel calls natively)", () => {
    expect(prefersSequentialToolCalls("zai.glm-5")).toBe(false);
    expect(prefersSequentialToolCalls("qwen.qwen3-coder-480b-a35b-v1:0")).toBe(
      false,
    );
  });
});

describe("OpenAI reasoning effort support", () => {
  it("supports the requested GPT-5.6 effort levels", () => {
    expect(getOpenAIReasoningEfforts("gpt-5.6-sol")).toEqual([
      "low",
      "medium",
      "high",
      "xhigh",
      "max",
    ]);
    expect(modelSupportsOpenAIReasoning("gpt-5.6-terra")).toBe(true);
    expect(modelSupportsOpenAIReasoning("gpt-5.6-luna")).toBe(true);
    expect(normalizeOpenAIReasoningEffort("gpt-5.6-sol", "ultra")).toBe("max");
  });

  it("supports GPT-5.5 and o-series reasoning models", () => {
    expect(modelSupportsOpenAIReasoning("gpt-5.5")).toBe(true);
    expect(modelSupportsOpenAIReasoning("gpt-5.5-2026-04-23")).toBe(true);
    expect(modelSupportsOpenAIReasoning("o3-mini")).toBe(true);
  });

  it("uses verified effort support for smaller and Codex models", () => {
    expect(getOpenAIReasoningEfforts("gpt-5-nano")).toEqual([
      "minimal",
      "low",
      "medium",
      "high",
    ]);
    expect(getOpenAIReasoningEfforts("gpt-5.1-codex-mini")).toEqual([
      "low",
      "medium",
      "high",
    ]);
    expect(getOpenAIReasoningEfforts("gpt-5.1-codex-max")).toEqual([
      "low",
      "medium",
      "high",
      "xhigh",
    ]);
    expect(getOpenAIReasoningEfforts("gpt-5.3-codex")).toEqual([
      "low",
      "medium",
      "high",
      "xhigh",
    ]);
    expect(modelSupportsOpenAIReasoning("gpt-future-99")).toBe(false);
  });

  it("defaults only supported reasoning models to medium", () => {
    expect(normalizeOpenAIReasoningEffort("gpt-5.5")).toBe(
      DEFAULT_OPENAI_REASONING_EFFORT,
    );
  });
});

describe("open-weight gateway models", () => {
  it.each([
    {
      id: "xiaomi/mimo-v2.6-pro",
      name: "MiMo-V2.6-Pro",
      provider: "openrouter",
      contextLength: 1_050_000,
      maxOutputTokens: 131_072,
    },
    {
      id: "concentrate:mimo-v2.6-pro",
      name: "MiMo V2.6 Pro",
      provider: "concentrate",
      contextLength: 1_048_576,
      maxOutputTokens: 131_072,
    },
    {
      id: "moonshotai/kimi-k3",
      name: "Kimi K3",
      provider: "openrouter",
      contextLength: 1_048_576,
      maxOutputTokens: 131_072,
    },
    {
      id: "concentrate:kimi-k3",
      name: "Kimi K3",
      provider: "concentrate",
      contextLength: 1_048_576,
      maxOutputTokens: 32_768,
    },
    {
      id: "concentrate:kimi-k3-1-pro",
      name: "Kimi K3.1 Pro",
      provider: "concentrate",
      contextLength: 1_048_576,
      maxOutputTokens: 32_768,
    },
    {
      id: "qwen/qwen3.8-max-0902",
      name: "Qwen3.8 Max (0902)",
      provider: "openrouter",
      contextLength: 1_000_000,
      maxOutputTokens: 131_072,
    },
    {
      id: "qwen/qwen3.8-27b",
      name: "Qwen3.8 27B",
      provider: "openrouter",
      contextLength: 1_000_000,
      maxOutputTokens: 131_072,
    },
    {
      id: "qwen/qwen3.8-flash",
      name: "Qwen3.8 Flash",
      provider: "openrouter",
      contextLength: 1_000_000,
      maxOutputTokens: 131_072,
    },
    {
      id: "concentrate:qwen3.8-max",
      name: "Qwen3.8 Max",
      provider: "concentrate",
      contextLength: 256_000,
      maxOutputTokens: 32_768,
    },
    {
      id: "concentrate:qwen3.8-27b",
      name: "Qwen3.8 27B",
      provider: "concentrate",
      contextLength: 262_144,
      maxOutputTokens: 32_768,
    },
    {
      id: "deepseek/deepseek-v4.1-flash-1017",
      name: "DeepSeek V4.1 Flash 1017",
      provider: "openrouter",
      contextLength: 1_048_576,
      maxOutputTokens: 384_000,
    },
    {
      id: "deepseek/deepseek-v4-pro-0813",
      name: "DeepSeek V4 Pro 0813",
      provider: "openrouter",
      contextLength: 1_048_576,
      maxOutputTokens: 384_000,
    },
    {
      id: "concentrate:deepseek-v4-1-flash",
      name: "DeepSeek V4.1 Flash",
      provider: "concentrate",
      contextLength: 1_000_000,
      maxOutputTokens: 32_768,
    },
    {
      id: "concentrate:deepseek-v4-1-flash-1017",
      name: "DeepSeek V4.1 Flash 1017",
      provider: "concentrate",
      contextLength: 1_048_576,
      maxOutputTokens: 131_072,
    },
    {
      id: "concentrate:deepseek-v4-pro-0813",
      name: "DeepSeek V4 Pro 0813",
      provider: "concentrate",
      contextLength: 1_048_576,
      maxOutputTokens: 384_000,
    },
  ])("registers $id with its gateway limits", ({
    id,
    maxOutputTokens,
    ...info
  }) => {
    expect(getModelInfo(id)).toMatchObject(info);
    expect(getMaxOutputTokens(id)).toBe(maxOutputTokens);
  });

  it.each([
    "concentrate:mimo-v2.6-pro",
    "concentrate:kimi-k3",
    "concentrate:kimi-k3-1-pro",
    "concentrate:qwen3.8-max",
    "concentrate:qwen3.8-27b",
    "concentrate:deepseek-v4-1-flash",
    "concentrate:deepseek-v4-1-flash-1017",
    "concentrate:deepseek-v4-pro-0813",
  ])("offers every effort Concentrate can route for %s", (id) => {
    expect(modelSupportsOpenAIReasoning(id)).toBe(true);
    expect(getOpenAIReasoningEfforts(id)).toEqual([
      "low",
      "medium",
      "high",
      "xhigh",
      "max",
    ]);
    expect(normalizeOpenAIReasoningEffort(id)).toBe("medium");
    expect(normalizeOpenAIReasoningEffort(id, "max")).toBe("max");
  });
});
