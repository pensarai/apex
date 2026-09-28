import { createOpenAI } from "@ai-sdk/openai";
import {
  APICallError,
  type JSONObject,
  type LanguageModelV3,
  type LanguageModelV3CallOptions,
  type LanguageModelV3GenerateResult,
  type SharedV3ProviderMetadata,
} from "@ai-sdk/provider";

export const CONCENTRATE_BASE_URL = "https://api.concentrate.ai/v1";
export const CONCENTRATE_GLM_5_3_MODEL_ID = "concentrate:glm-5.3";

const RETRYABLE_STATUSES = new Set([424, 429, 500, 503, 504]);

export type ConcentrateFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type ConcentrateErrorBody = {
  error?: string | { message?: string };
  message?: string;
  model?: string;
};

export type ConcentrateCostMetadata = {
  total: number;
  byok: boolean;
  breakdown: JSONObject;
};

export type ConcentrateResponseMetadata = {
  model?: string;
  cost?: ConcentrateCostMetadata;
};

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function responseHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
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

function isJsonObject(value: unknown): value is JSONObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.values(value).every((entry) => {
    if (
      entry === null ||
      typeof entry === "string" ||
      typeof entry === "boolean"
    ) {
      return true;
    }
    if (typeof entry === "number") return Number.isFinite(entry);
    if (Array.isArray(entry)) {
      return entry.every(
        (item) =>
          item === null ||
          typeof item === "string" ||
          typeof item === "boolean" ||
          (typeof item === "number" && Number.isFinite(item)) ||
          isJsonObject(item),
      );
    }
    return isJsonObject(entry);
  });
}

export function extractConcentrateResponseMetadata(
  value: unknown,
): ConcentrateResponseMetadata | undefined {
  if (!isJsonObject(value)) return undefined;
  const response = isJsonObject(value.response) ? value.response : value;
  const model = typeof response.model === "string" ? response.model : undefined;
  const rawCost = response.cost;
  const cost =
    isJsonObject(rawCost) &&
    typeof rawCost.total === "number" &&
    Number.isFinite(rawCost.total) &&
    typeof rawCost.byok === "boolean" &&
    isJsonObject(rawCost.breakdown)
      ? {
          total: rawCost.total,
          byok: rawCost.byok,
          breakdown: rawCost.breakdown,
        }
      : undefined;

  if (!model && !cost) return undefined;
  return { model, cost };
}

function mergeConcentrateMetadata(
  current: ConcentrateResponseMetadata,
  next: ConcentrateResponseMetadata | undefined,
): ConcentrateResponseMetadata {
  if (!next) return current;
  return {
    model: next.model ?? current.model,
    cost: next.cost ?? current.cost,
  };
}

function withConcentrateMetadata(
  providerMetadata: SharedV3ProviderMetadata | undefined,
  metadata: ConcentrateResponseMetadata,
): SharedV3ProviderMetadata {
  const concentrate: JSONObject = {
    ...(providerMetadata?.concentrate ?? {}),
    ...(metadata.model ? { model: metadata.model } : {}),
    ...(metadata.cost ? { cost: metadata.cost } : {}),
  };
  return { ...providerMetadata, concentrate };
}

function addGenerateMetadata(
  result: LanguageModelV3GenerateResult,
): LanguageModelV3GenerateResult {
  const metadata = extractConcentrateResponseMetadata(result.response?.body);
  if (!metadata) return result;
  return {
    ...result,
    providerMetadata: withConcentrateMetadata(
      result.providerMetadata,
      metadata,
    ),
  };
}

export function createConcentrateFetch(
  fetchFn: ConcentrateFetch = (input, init) => globalThis.fetch(input, init),
): ConcentrateFetch {
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
        ...(forceReasoning
          ? { forceReasoning: true, reasoningSummary: "auto" }
          : {}),
      },
    },
  });

  return {
    specificationVersion: model.specificationVersion,
    provider: model.provider,
    modelId: model.modelId,
    supportedUrls: model.supportedUrls,
    doGenerate: async (options) =>
      addGenerateMetadata(await model.doGenerate(withDefaults(options))),
    doStream: async (options) => {
      const includeRawChunks = options.includeRawChunks;
      const result = await model.doStream(
        withDefaults({ ...options, includeRawChunks: true }),
      );
      let metadata: ConcentrateResponseMetadata = {};

      return {
        ...result,
        stream: result.stream.pipeThrough(
          new TransformStream({
            transform(part, controller) {
              if (part.type === "raw") {
                metadata = mergeConcentrateMetadata(
                  metadata,
                  extractConcentrateResponseMetadata(part.rawValue),
                );
                if (includeRawChunks) controller.enqueue(part);
                return;
              }
              if (part.type === "response-metadata" && part.modelId) {
                metadata = mergeConcentrateMetadata(metadata, {
                  model: part.modelId,
                });
              }
              if (part.type === "finish") {
                controller.enqueue({
                  ...part,
                  providerMetadata: withConcentrateMetadata(
                    part.providerMetadata,
                    metadata,
                  ),
                });
                return;
              }
              controller.enqueue(part);
            },
          }),
        ),
      };
    },
  };
}

export function createConcentrateModel(
  modelId: string,
  options: { apiKey?: string; fetch?: ConcentrateFetch },
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
    fetch: createConcentrateFetch(options.fetch) as unknown as typeof fetch,
  });
  return withConcentrateDefaults(
    concentrate.responses(upstreamModelId),
    modelId === CONCENTRATE_GLM_5_3_MODEL_ID,
  );
}
