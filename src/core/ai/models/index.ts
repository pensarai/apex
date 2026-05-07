import type { AIModel, ModelInfo } from "../ai";

// Anthropic, OpenAI, Google, Bedrock — auto-generated from SDK type definitions.
// Re-generate after bumping SDK packages: bun run generate:models
import { ANTHROPIC_MODELS } from "./anthropic";
import { OPENAI_MODELS } from "./openai";
import { GOOGLE_MODELS } from "./google";
import { BEDROCK_MODELS } from "./bedrock";

// OpenRouter — curated manually (SDK doesn't enumerate models).
import { OPENROUTER_MODELS } from "./openrouter";
import { PENSAR_MODELS } from "./pensar";
import { INCEPTION_MODELS } from "./inception";

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
  // Latest-tier Claude (4.6, 4.7) ship 128K output. Match these BEFORE the
  // generic `claude-opus-4-` / `claude-sonnet-4-` catch-alls below — those
  // exist only as a 32K/64K floor for older 4.x revisions and would
  // otherwise clamp a top-tier model to a 4× smaller budget.
  if (
    modelId.includes("claude-opus-4-6") ||
    modelId.includes("claude-opus-4-7") ||
    modelId.includes("claude-sonnet-4-6") ||
    modelId.includes("claude-sonnet-4-7")
  ) {
    return 128_000;
  }
  if (
    modelId.includes("claude-sonnet-4-5") ||
    modelId.includes("claude-opus-4-5") ||
    modelId.includes("claude-haiku-4-5")
  ) {
    return 64_000;
  }
  if (modelId.includes("claude-opus-4-1")) {
    return 32_000;
  }
  if (
    modelId.includes("claude-sonnet-4-") ||
    modelId.includes("claude-3-7-sonnet")
  ) {
    return 64_000;
  }
  if (modelId.includes("claude-opus-4-")) {
    return 32_000;
  }
  if (modelId.includes("claude-3-5-haiku")) {
    return 8_192;
  }
  return 4_096;
}
