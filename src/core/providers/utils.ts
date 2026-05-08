import type { Config } from "../config/config";
import { AVAILABLE_MODELS, type ModelInfo } from "../ai";
import {
  AVAILABLE_PROVIDERS,
  type ConfiguredProvider,
  type ProviderType,
} from "./types";

const PROVIDER_PREFERENCE_ORDER: ProviderType[] = [
  "pensar",
  "anthropic",
  "openai",
  "google",
  "openrouter",
  "bedrock",
];

const PREFERRED_MODEL_BY_PROVIDER: Record<string, string> = {
  pensar: "pensar:anthropic.claude-opus-4-6-v1",
  anthropic: "claude-opus-4-6",
  openai: "gpt-5.2-pro",
  google: "gemini-3.1-pro-preview",
  openrouter: "anthropic/claude-opus-4.6",
  bedrock: "anthropic.claude-opus-4-6-v1",
};

export function getConfiguredProviders(config: Config): ConfiguredProvider[] {
  return AVAILABLE_PROVIDERS.map((provider) => {
    const configured = isProviderConfigured(provider.id, config);
    return {
      ...provider,
      configured,
      hasValidKey: configured,
    };
  });
}

function isProviderConfigured(
  providerId: ProviderType,
  config: Config,
): boolean {
  switch (providerId) {
    case "anthropic":
      return !!config.anthropicAPIKey;
    case "openai":
      return !!config.openAiAPIKey;
    case "google":
      return !!config.googleAPIKey;
    case "openrouter":
      return !!config.openRouterAPIKey;
    case "inception":
      return !!config.inceptionAPIKey;
    case "bedrock":
      return !!config.bedrockAPIKey;
    case "local":
      return !!(
        config.localModelUrl ||
        config.localModelName ||
        process.env.LOCAL_MODEL_URL
      );
    case "pensar":
      return !!(config.pensarAPIKey || config.accessToken);
    default:
      return false;
  }
}

export function hasAnyProviderConfigured(config: Config): boolean {
  return (
    !!config.anthropicAPIKey ||
    !!config.openAiAPIKey ||
    !!config.googleAPIKey ||
    !!config.openRouterAPIKey ||
    !!config.inceptionAPIKey ||
    !!config.bedrockAPIKey ||
    !!config.localModelUrl ||
    !!config.localModelName ||
    !!process.env.LOCAL_MODEL_URL ||
    !!config.pensarAPIKey ||
    !!config.accessToken
  );
}

function getModelsByProvider(providerId: ProviderType): ModelInfo[] {
  return AVAILABLE_MODELS.filter((model) => model.provider === providerId);
}

export function getAvailableModels(config: Config): ModelInfo[] {
  const models = AVAILABLE_MODELS.filter((model) => {
    return isProviderConfigured(model.provider as ProviderType, config);
  });

  if (isProviderConfigured("local", config) && config.localModelName) {
    models.push({
      id: config.localModelName,
      name: config.localModelName,
      provider: "local",
    });
  }

  return models;
}

/**
 * Dynamically select the best default model based on which providers are
 * configured.  Priority order: Pensar → Anthropic → OpenAI → Google →
 * OpenRouter → Bedrock.  Within each provider the preferred model is an
 * opus-class / flagship model; falls back to the first available model for
 * that provider if the preferred one isn't found.
 */
export function getDefaultModelForConfig(config: Config): ModelInfo | null {
  const available = getAvailableModels(config);
  if (available.length === 0) return null;

  const byProvider = new Map<string, ModelInfo[]>();
  for (const m of available) {
    const list = byProvider.get(m.provider) || [];
    list.push(m);
    byProvider.set(m.provider, list);
  }

  for (const provider of PROVIDER_PREFERENCE_ORDER) {
    const models = byProvider.get(provider);
    if (!models || models.length === 0) continue;

    const preferredId = PREFERRED_MODEL_BY_PROVIDER[provider];
    if (preferredId) {
      const preferred = models.find((m) => m.id === preferredId);
      if (preferred) return preferred;
    }
    return models[0]!;
  }

  return available[0] ?? null;
}
