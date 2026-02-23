import type { Config } from "../config/config";
import { AVAILABLE_MODELS } from "../ai/models";
import { type ModelInfo } from "../ai";
import {
  AVAILABLE_PROVIDERS,
  type ConfiguredProvider,
  type ProviderType,
} from "./types";

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

export function isProviderConfigured(
  providerId: ProviderType,
  config: Config,
): boolean {
  switch (providerId) {
    case "anthropic":
      return !!config.anthropicAPIKey;
    case "openai":
      return !!config.openAiAPIKey;
    case "openrouter":
      return !!config.openRouterAPIKey;
    case "bedrock":
      return !!config.bedrockAPIKey;
    case "local":
      return !!(
        config.localModelUrl ||
        config.localModelName ||
        process.env.LOCAL_MODEL_URL
      );
    case "pensar":
      return !!config.pensarAPIKey;
    default:
      return false;
  }
}

export function hasAnyProviderConfigured(config: Config): boolean {
  return (
    !!config.anthropicAPIKey ||
    !!config.openAiAPIKey ||
    !!config.openRouterAPIKey ||
    !!config.bedrockAPIKey ||
    !!config.localModelUrl ||
    !!config.localModelName ||
    !!process.env.LOCAL_MODEL_URL ||
    !!config.pensarAPIKey
  );
}

export function getModelsByProvider(providerId: ProviderType): ModelInfo[] {
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
