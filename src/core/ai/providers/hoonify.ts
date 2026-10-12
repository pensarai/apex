import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import type { LanguageModelV3 } from "@ai-sdk/provider";
import {
  HOONIFY_BASE_URL,
  type HoonifyModel,
  resolveHoonifyModel,
} from "../../hoonify";

export function createHoonifyModel(
  id: string,
  options: { apiKey?: string; models?: HoonifyModel[] },
): LanguageModelV3 {
  const apiKey = (options.apiKey ?? process.env.HOONIFY_API_KEY)?.trim();
  if (!apiKey)
    throw new Error("Set HOONIFY_API_KEY or connect Hoonify in /providers.");
  const model = resolveHoonifyModel(id, options.models);
  return createOpenAICompatible({
    name: "hoonify",
    baseURL: HOONIFY_BASE_URL,
    apiKey,
    supportsStructuredOutputs: true,
    transformRequestBody: (body) => ({
      ...body,
      max_tokens: Math.min(
        typeof body.max_tokens === "number"
          ? body.max_tokens
          : model.maxOutputTokens,
        model.maxOutputTokens,
      ),
    }),
  }).chatModel(model.id);
}
