import type { AIModel, ModelInfo } from "../ai";

// Anthropic, OpenAI, Bedrock — auto-generated from SDK type definitions.
// Re-generate after bumping SDK packages: bun run generate:models
import { ANTHROPIC_MODELS } from "./anthropic";
import { OPENAI_MODELS } from "./openai";
import { BEDROCK_MODELS } from "./bedrock";

// OpenRouter — curated manually (SDK doesn't enumerate models).
import { OPENROUTER_MODELS } from "./openrouter";

export const AVAILABLE_MODELS: ModelInfo[] = [
  ...ANTHROPIC_MODELS,
  ...OPENAI_MODELS,
  ...BEDROCK_MODELS,
  ...OPENROUTER_MODELS,
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
