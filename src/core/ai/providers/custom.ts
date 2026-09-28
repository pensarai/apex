import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import type { LanguageModelV3 } from "@ai-sdk/provider";
import {
  type CustomProviders,
  resolveCustomApiKey,
  resolveCustomModel,
} from "../../config/customProviders";

export function createCustomModel(
  id: string,
  providers?: CustomProviders,
): LanguageModelV3 {
  const { providerId, provider, model } = resolveCustomModel(id, providers);
  return createOpenAICompatible({
    name: `custom-${providerId}`,
    baseURL: provider.baseUrl,
    apiKey: resolveCustomApiKey(provider),
    headers: provider.headers,
    transformRequestBody: (body) => ({
      ...body,
      ...provider.requestBody,
      max_tokens: Math.min(
        typeof body.max_tokens === "number"
          ? body.max_tokens
          : model.maxOutputTokens,
        model.maxOutputTokens,
      ),
    }),
  }).chatModel(model.id);
}
