import { createOpenAI } from "@ai-sdk/openai";
import {
  APICallError,
  type LanguageModelV3,
  type LanguageModelV3CallOptions,
} from "@ai-sdk/provider";

export const CONCENTRATE_BASE_URL = "https://api.concentrate.ai/v1";
export const CONCENTRATE_GLM_5_3_MODEL_ID = "concentrate:glm-5.3";

const RETRYABLE_STATUSES = new Set([424, 429, 500, 503, 504]);

type ConcentrateErrorBody = {
  error?: string | { message?: string };
  message?: string;
  model?: string;
};

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function responseHeaders(headers: Headers): Record<string, string> {
  return Object.fromEntries(headers.entries());
}

function parseErrorBody(body: string): {
  data?: ConcentrateErrorBody;
  message?: string;
} {
  try {
    const data = JSON.parse(body) as ConcentrateErrorBody;
    const nested =
      typeof data.error === "object" ? data.error.message : undefined;
    const direct = typeof data.error === "string" ? data.error : undefined;
    return { data, message: data.message ?? nested ?? direct };
  } catch {
    return {};
  }
}

export function createConcentrateFetch(
  fetchFn: typeof fetch = globalThis.fetch,
): typeof fetch {
  return async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const response = await fetchFn(input, init);
    if (response.ok) return response;

    const body = await response.text();
    const parsed = parseErrorBody(body);
    throw new APICallError({
      message:
        parsed.message ??
        `Concentrate request failed with HTTP ${response.status}`,
      url: requestUrl(input),
      requestBodyValues: undefined,
      statusCode: response.status,
      responseHeaders: responseHeaders(response.headers),
      responseBody: body,
      data: parsed.data,
      isRetryable: RETRYABLE_STATUSES.has(response.status),
    });
  };
}

function withConcentrateDefaults(
  model: LanguageModelV3,
  forceReasoning: boolean,
): LanguageModelV3 {
  const withDefaults = (
    options: LanguageModelV3CallOptions,
  ): LanguageModelV3CallOptions => ({
    ...options,
    providerOptions: {
      ...options.providerOptions,
      openai: {
        ...options.providerOptions?.openai,
        store: false,
        ...(forceReasoning ? { forceReasoning: true } : {}),
      },
    },
  });

  return {
    specificationVersion: model.specificationVersion,
    provider: model.provider,
    modelId: model.modelId,
    supportedUrls: model.supportedUrls,
    doGenerate: (options) => model.doGenerate(withDefaults(options)),
    doStream: (options) => model.doStream(withDefaults(options)),
  };
}

export function createConcentrateModel(
  modelId: string,
  options: { apiKey?: string; fetch?: typeof fetch },
): LanguageModelV3 {
  const apiKey = options.apiKey?.trim();
  if (!apiKey) {
    throw new Error(
      "Concentrate is not configured. Set CONCENTRATE_API_KEY first.",
    );
  }
  if (!modelId.startsWith("concentrate:")) {
    throw new Error(
      `Concentrate model IDs must start with "concentrate:": ${modelId}`,
    );
  }

  const upstreamModelId = modelId.slice("concentrate:".length);
  if (!upstreamModelId) {
    throw new Error("Concentrate model ID cannot be empty.");
  }

  const concentrate = createOpenAI({
    name: "concentrate",
    apiKey,
    baseURL: CONCENTRATE_BASE_URL,
    fetch: createConcentrateFetch(options.fetch),
  });
  return withConcentrateDefaults(
    concentrate.responses(upstreamModelId),
    modelId === CONCENTRATE_GLM_5_3_MODEL_ID,
  );
}
