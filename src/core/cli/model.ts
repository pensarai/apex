import {
  type CustomProviders,
  parseCustomModelId,
  resolveCustomApiKey,
  resolveCustomModel,
} from "../config/customProviders";
import { type HoonifyModel, resolveHoonifyModel } from "../hoonify";
import { type OllamaCatalog, resolveOllamaModel } from "../ollama";

export function resolveExplicitCliModel(options: {
  model?: string;
  provider?: string;
  customProviders?: CustomProviders;
  hoonifyModels?: HoonifyModel[];
  ollama?: OllamaCatalog;
  hoonifyCatalogError?: string;
}): string | undefined {
  const { model, provider, customProviders } = options;
  if (provider && !model) throw new Error("--model-provider requires --model.");
  if (!model) return undefined;
  const id =
    provider === "hoonify" ||
    (provider === "ollama" && !customProviders?.ollama)
      ? `${provider}:${model}`
      : provider
        ? `custom:${provider}:${model}`
        : model;
  if (id.startsWith("ollama:")) resolveOllamaModel(id, options.ollama);
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
