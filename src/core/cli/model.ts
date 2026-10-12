import {
  type CustomProviders,
  parseCustomModelId,
  resolveCustomApiKey,
  resolveCustomModel,
} from "../config/customProviders";
import { type HoonifyModel, resolveHoonifyModel } from "../hoonify";

export function resolveExplicitCliModel(options: {
  model?: string;
  provider?: string;
  customProviders?: CustomProviders;
  hoonifyModels?: HoonifyModel[];
  hoonifyCatalogError?: string;
}): string | undefined {
  const { model, provider, customProviders } = options;
  if (provider && !model) throw new Error("--model-provider requires --model.");
  if (!model) return undefined;
  const id =
    provider === "hoonify"
      ? `hoonify:${model}`
      : provider
        ? `custom:${provider}:${model}`
        : model;
  if (id.startsWith("hoonify:")) {
    if (options.hoonifyCatalogError)
      throw new Error(options.hoonifyCatalogError);
    resolveHoonifyModel(id, options.hoonifyModels);
  }
  if (parseCustomModelId(id)) {
    const resolved = resolveCustomModel(id, customProviders);
    resolveCustomApiKey(resolved.provider);
  }
  return id;
}
