import { createOpenAI } from "@ai-sdk/openai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import type { LanguageModelV3 } from "@ai-sdk/provider";
import { wrapLanguageModel } from "ai";
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
  if (provider.apiType === "responses") {
    if (!provider.apiKeyEnv)
      throw new Error("Responses custom providers require apiKeyEnv.");
    if (provider.requestBody)
      throw new Error("requestBody is only supported for Chat Completions.");
    const responsesModel = createOpenAI({
      name: `custom-${providerId}`,
      baseURL: provider.baseUrl,
      apiKey: resolveCustomApiKey(provider),
      headers: provider.headers,
    }).responses(model.id);
    return wrapLanguageModel({
      model: responsesModel,
      middleware: {
        specificationVersion: "v3",
        transformParams: async ({ params }) => ({
          ...params,
          maxOutputTokens: Math.min(
            params.maxOutputTokens ?? model.maxOutputTokens,
            model.maxOutputTokens,
          ),
          ...(model.reasoningEffort && {
            providerOptions: {
              ...params.providerOptions,
              openai: {
                ...params.providerOptions?.openai,
                // Unlisted model IDs need this to send reasoning.effort.
                forceReasoning: true,
                reasoningEffort: model.reasoningEffort,
              },
            },
          }),
        }),
      },
    });
  }
  if (model.reasoningEffort)
    throw new Error("reasoningEffort requires the Responses API.");
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
