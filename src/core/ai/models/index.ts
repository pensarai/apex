import type { AIModel, ModelInfo } from "../ai";

// Anthropic, OpenAI, Google, Bedrock — auto-generated from SDK type definitions.
// Re-generate after bumping SDK packages: bun run generate:models
import { ANTHROPIC_MODELS } from "./anthropic";
import { BEDROCK_MODELS } from "./bedrock";
import { GOOGLE_MODELS } from "./google";
import { INCEPTION_MODELS } from "./inception";
import { OPENAI_MODELS } from "./openai";
// OpenRouter — curated manually (SDK doesn't enumerate models).
import { OPENROUTER_MODELS } from "./openrouter";
import { PENSAR_MODELS } from "./pensar";

export const AVAILABLE_MODELS: ModelInfo[] = [
  ...ANTHROPIC_MODELS,
  ...OPENAI_MODELS,
  ...GOOGLE_MODELS,
  ...BEDROCK_MODELS,
  ...OPENROUTER_MODELS,
  ...PENSAR_MODELS,
  ...INCEPTION_MODELS,
];

export function getModelInfo(model: AIModel): ModelInfo {
  return (
    AVAILABLE_MODELS.find((m) => m.id === model) ?? {
      id: model,
      name: model,
      provider: "local",
    }
  );
}

/**
 * Single source of truth for a model's default `max_tokens`. Both
 * `streamResponse`'s budget and the Pensar gateway formatter must agree,
 * so the lookup lives next to the registry it queries against.
 *
 * Adding a Claude model? Add a pattern AND a regression row in
 * `models.test.ts:"recognizes Claude tier-specific budgets"`.
 */
export function getMaxOutputTokens(modelId: string): number {
  const fromPattern = lookupOutputBudgetByPattern(modelId);
  const ctx = AVAILABLE_MODELS.find((m) => m.id === modelId)?.contextLength;
  // Reserve ≥25% of the window for input on tiny-context legacy models.
  if (ctx && fromPattern >= ctx * 0.75) {
    return Math.floor(ctx * 0.5);
  }
  return fromPattern;
}

function lookupOutputBudgetByPattern(modelId: string): number {
  // OpenRouter uses dots in Claude version numbers (anthropic/claude-opus-4.6)
  // while native Anthropic uses dashes (claude-opus-4-6-20250929). Normalize
  // digit.digit sequences to dashes so all Claude patterns match both forms.
  const n = modelId.replace(/(\d)\.(\d)/g, "$1-$2");

  // Latest-tier Claude (4.6, 4.7, 4.8) ship 128K output. Match these BEFORE
  // the generic `claude-opus-4-` / `claude-sonnet-4-` catch-alls below —
  // those exist only as a 32K/64K floor for older 4.x revisions and would
  // otherwise clamp a top-tier model to a 4× smaller budget.
  if (
    n.includes("claude-opus-4-6") ||
    n.includes("claude-opus-4-7") ||
    n.includes("claude-opus-4-8") ||
    n.includes("claude-sonnet-4-6") ||
    n.includes("claude-sonnet-4-7") ||
    n.includes("claude-sonnet-4-8")
  ) {
    return 128_000;
  }
  if (
    n.includes("claude-sonnet-4-5") ||
    n.includes("claude-opus-4-5") ||
    n.includes("claude-haiku-4-5")
  ) {
    return 64_000;
  }
  if (n.includes("claude-opus-4-1")) {
    return 32_000;
  }
  if (n.includes("claude-sonnet-4-") || n.includes("claude-3-7-sonnet")) {
    return 64_000;
  }
  if (n.includes("claude-opus-4-")) {
    return 32_000;
  }
  // Bare `claude-{sonnet,opus}-4` (OpenRouter) — generation 4 with no tier
  // suffix. Anthropic-canonical IDs always carry a date / `-v1` suffix so
  // they hit the dashed branches above; the negative-lookahead ensures the
  // bare-form branches only trigger when nothing follows the `-4`.
  if (/claude-sonnet-4(?![-\d])/.test(n)) {
    return 64_000;
  }
  if (/claude-opus-4(?![-\d])/.test(n)) {
    return 32_000;
  }
  if (n.includes("claude-3-5-haiku") || n.includes("claude-3-5-sonnet")) {
    return 8_192;
  }

  // OpenAI families. `getMaxOutputTokens` is now the single source of truth
  // for both `streamResponse`'s budget math AND the value passed as
  // `maxOutputTokens` to `streamText`, so an underestimate here would make
  // `fitMessagesToContext` overly permissive on input — exactly the
  // overflow class this PR closes. Defaults below come from each family's
  // documented max output; the per-model `contextLength` clamp in
  // `getMaxOutputTokens` handles legacy small-window variants.
  if (modelId.includes("gpt-5")) {
    return 128_000;
  }
  if (modelId.includes("gpt-4.1")) {
    return 32_000;
  }
  if (modelId.includes("gpt-4o")) {
    return 16_000;
  }
  // Reasoning models (o1 / o3 / o4-*) emit up to ~100K incl. reasoning tokens.
  if (
    /\bo1\b/.test(modelId) ||
    /\bo3(\b|-)/.test(modelId) ||
    /\bo4(\b|-)/.test(modelId)
  ) {
    return 100_000;
  }
  if (modelId.includes("gpt-3.5")) {
    return 4_096;
  }

  // Google Gemini families.
  if (modelId.includes("gemini-3")) {
    return 64_000;
  }
  if (modelId.includes("gemini-2.5")) {
    return 65_000;
  }
  // Version-less `*-latest` aliases (registered with 1M context) point to
  // current top-tier Gemini, NOT the legacy 2.0/1.5 generations. Match
  // these BEFORE the `gemini-pro` / `gemini-flash` catch-alls below,
  // otherwise they'd inherit the 8192-token legacy budget — and since
  // `getMaxOutputTokens` is now passed explicitly to `streamText`, that
  // would hard-cap them at 8K instead of the 65K modern default.
  if (
    modelId === "gemini-pro-latest" ||
    modelId === "gemini-flash-latest" ||
    modelId === "gemini-flash-lite-latest"
  ) {
    return 65_000;
  }
  if (
    modelId.includes("gemini-2.0") ||
    modelId.includes("gemini-1.5") ||
    modelId.includes("gemini-pro") ||
    modelId.includes("gemini-flash")
  ) {
    return 8_192;
  }

  // MiniMax M3: match our top-tier Opus output budget (128K) rather than the
  // model's advertised 512K max, keeping ample input headroom for agentic work.
  if (modelId.includes("minimax-m3")) {
    return 128_000;
  }

  // GLM 5.2 ships a 131.1K (128Ki) max-output window over its 1M context.
  if (modelId.includes("glm-5.2")) {
    return 131_072;
  }

  return 4_096;
}
