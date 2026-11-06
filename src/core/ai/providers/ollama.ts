import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { type OllamaCatalog, resolveOllamaModel } from "../../ollama";

export function createOllamaModel(id: string, catalog?: OllamaCatalog) {
  const { model, baseURL } = resolveOllamaModel(id, catalog);
  return createOpenAICompatible({
    name: "ollama",
    baseURL: `${baseURL}/v1`,
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
