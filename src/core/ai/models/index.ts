import type { AIModel, ModelInfo } from "../ai";
import { ANTHROPIC_MODELS } from "./anthropic";
import { OPENROUTER_MODELS } from "./openrouter";
import { BEDROCK_MODELS } from "./bedrock";
import { OPENAI_MODELS } from "./openai";
export const AVAILABLE_MODELS: ModelInfo[] = [
  ...ANTHROPIC_MODELS,
  ...OPENROUTER_MODELS,
  ...BEDROCK_MODELS,
  ...OPENAI_MODELS,
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
