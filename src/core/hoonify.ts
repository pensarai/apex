import { z } from "zod";

export const HOONIFY_BASE_URL = "https://api.hoonify.ai/v1";

// Hoonify's deployed context limit is lower than its advertised model capacity.
const MODEL_CONTEXT_DEFAULTS = new Map([["zai-org/GLM-5.2", 500_000]]);

// Used only when both API metadata and a model-specific default are missing.
const FALLBACK_CONTEXT_WINDOW = 32_768;

export interface HoonifyModel {
  id: string;
  contextLength: number;
  maxOutputTokens: number;
}

const catalogSchema = z.object({
  data: z.array(
    z.object({
      id: z.string().trim().min(1),
      // Treat explicit null metadata like a missing field when choosing fallbacks.
      context_window: z.number().int().min(4).nullish(),
    }),
  ),
});

const contextWindowsSchema = z.record(
  z.string().min(1),
  z.number().int().min(4).max(Number.MAX_SAFE_INTEGER),
);

function readContextWindowOverrides(): Record<string, number> | undefined {
  const value = process.env.HOONIFY_CONTEXT_WINDOWS?.trim();
  if (!value) return undefined;
  try {
    return contextWindowsSchema.parse(JSON.parse(value));
  } catch {
    throw new Error(
      "HOONIFY_CONTEXT_WINDOWS must be a JSON object mapping exact model IDs to integer context windows between 4 and Number.MAX_SAFE_INTEGER.",
    );
  }
}

function applyContextWindowOverrides(
  models: HoonifyModel[],
  overrides: Record<string, number> | undefined,
): HoonifyModel[] {
  if (!overrides) return models;
  return models.map((model) => {
    if (!Object.hasOwn(overrides, model.id)) return model;
    const contextLength = overrides[model.id];
    return {
      ...model,
      contextLength,
      maxOutputTokens: Math.min(
        model.maxOutputTokens,
        Math.floor(contextLength / 4),
      ),
    };
  });
}

// One account's catalog at a time; never reuse a catalog after a key change.
let cached:
  | {
      apiKey: string;
      expiresAt: number;
      models: Promise<HoonifyModel[]>;
    }
  | undefined;

export async function loadHoonifyModels(
  apiKey: string,
  refresh = false,
): Promise<HoonifyModel[]> {
  apiKey = apiKey.trim();
  if (!apiKey) throw new Error("Set HOONIFY_API_KEY to use Hoonify.");
  const overrides = readContextWindowOverrides();
  if (!refresh && cached?.apiKey === apiKey && cached.expiresAt > Date.now()) {
    return applyContextWindowOverrides(await cached.models, overrides);
  }
  const entry = {
    apiKey,
    expiresAt: Date.now() + 5 * 60_000,
    models: fetchHoonifyModels(apiKey),
  };
  cached = entry;
  try {
    return applyContextWindowOverrides(await entry.models, overrides);
  } catch (error) {
    if (cached === entry) cached = undefined;
    throw error;
  }
}

async function fetchHoonifyModels(apiKey: string): Promise<HoonifyModel[]> {
  let response: Response;
  let body: unknown;
  try {
    response = await fetch(`${HOONIFY_BASE_URL}/models`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (response.ok) body = await response.json();
  } catch {
    throw new Error(
      "Could not load Hoonify models. Check connectivity and retry.",
    );
  }
  if (response.status === 401 || response.status === 403) {
    throw new Error(
      "Hoonify rejected the API key. Check your key and model access.",
    );
  }
  if (!response.ok) {
    throw new Error(`Hoonify model catalog returned HTTP ${response.status}.`);
  }
  const parsed = catalogSchema.safeParse(body);
  if (!parsed.success) {
    const fields = [
      ...new Set(
        parsed.error.issues.map((issue) => issue.path.join(".") || "response"),
      ),
    ].slice(0, 3);
    throw new Error(
      `Hoonify returned a model catalog Apex could not read. Missing or invalid fields: ${fields.join(", ")}.`,
    );
  }
  if (parsed.data.data.length === 0) {
    throw new Error("No Hoonify models are available to this API key.");
  }
  if (
    new Set(parsed.data.data.map((model) => model.id)).size !==
    parsed.data.data.length
  ) {
    throw new Error("Hoonify returned duplicate model IDs.");
  }
  return parsed.data.data.map((model) => {
    const contextLength =
      model.context_window ??
      MODEL_CONTEXT_DEFAULTS.get(model.id) ??
      FALLBACK_CONTEXT_WINDOW;
    return {
      id: model.id,
      contextLength,
      // Hoonify documents no model-specific output limit.
      maxOutputTokens: Math.min(4096, Math.floor(contextLength / 4)),
    };
  });
}

export function resolveHoonifyModel(
  id: string,
  models?: HoonifyModel[],
): HoonifyModel {
  const model = models?.find((item) => `hoonify:${item.id}` === id);
  if (!model) {
    throw new Error(
      "Hoonify model is unavailable. Load the catalog with config.get() or reconnect Hoonify in /providers.",
    );
  }
  return model;
}
