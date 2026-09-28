import {
  type CustomProviders,
  parseCustomModelId,
  resolveCustomApiKey,
  resolveCustomModel,
} from "../config/customProviders";

export function resolveExplicitCliModel(options: {
  model?: string;
  provider?: string;
  customProviders?: CustomProviders;
}): string | undefined {
  const { model, provider, customProviders } = options;
  if (provider && !model) throw new Error("--model-provider requires --model.");
  if (!model) return undefined;
  const id = provider ? `custom:${provider}:${model}` : model;
  if (parseCustomModelId(id)) {
    const resolved = resolveCustomModel(id, customProviders);
    resolveCustomApiKey(resolved.provider);
  }
  return id;
}
