import type { AIModel, ModelInfo } from "../ai";
import { ANTHROPIC_MODELS } from "./anthropic";
import { OPENROUTER_MODELS } from "./openrouter";
import { BEDROCK_MODELS } from "./bedrock";
import { OPENAI_MODELS } from "./openai";

/**
 * Built-in available models
 */
export const BUILTIN_MODELS: ModelInfo[] = [
  ...ANTHROPIC_MODELS,
  ...OPENROUTER_MODELS,
  ...BEDROCK_MODELS,
  ...OPENAI_MODELS,
];

/**
 * Get all available models including those from plugins
 */
export function getAvailableModels(): ModelInfo[] {
  // Start with built-in models
  const models = [...BUILTIN_MODELS];
  
  // Try to add plugin models (lazy import to avoid circular deps)
  try {
    // Dynamic import would be used in real implementation
    // For now, we'll use the built-in models
    // Plugin models are added when the plugin manager is initialized
  } catch {
    // Plugins not loaded yet, use built-in only
  }
  
  return models;
}

/**
 * @deprecated Use getAvailableModels() instead for plugin support
 */
export const AVAILABLE_MODELS: ModelInfo[] = BUILTIN_MODELS;

export function getModelInfo(model: AIModel): ModelInfo {
  // Check built-in models first
  const builtinModel = BUILTIN_MODELS.find((m) => m.id === model);
  if (builtinModel) {
    return builtinModel;
  }
  
  // Check plugin models
  const allModels = getAvailableModels();
  const pluginModel = allModels.find((m) => m.id === model);
  if (pluginModel) {
    return pluginModel;
  }
  
  // Return a default for unknown models
  return {
    id: model,
    name: model,
    provider: "local",
  };
}
