import type { AIModelProvider, ModelInfo } from "../../../core/ai";

const PROVIDER_DISPLAY_NAMES: Record<AIModelProvider, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  google: "Google",
  openrouter: "OpenRouter",
  concentrate: "Concentrate",
  bedrock: "AWS Bedrock",
  "bedrock-mantle": "Bedrock Mantle",
  pensar: "Pensar",
  inception: "Inception",
  local: "Local LLM",
};

export function getProviderDisplayName(provider: AIModelProvider): string {
  return PROVIDER_DISPLAY_NAMES[provider];
}

function normalizeSearchText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

export function filterModels(
  models: ModelInfo[],
  searchQuery: string,
): ModelInfo[] {
  const terms = normalizeSearchText(searchQuery).split(/\s+/).filter(Boolean);
  if (terms.length === 0) return models;

  return models.filter((model) => {
    const searchableText = normalizeSearchText(
      `${model.name} ${model.id} ${model.provider} ${getProviderDisplayName(model.provider)}`,
    );
    return terms.every((term) => searchableText.includes(term));
  });
}
