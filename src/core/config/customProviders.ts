import { z } from "zod";

const providerIdSchema = z.string().regex(/^[a-zA-Z0-9_-]+$/);
const reservedRequestFields = new Set([
  "model",
  "messages",
  "tools",
  "tool_choice",
  "stream",
  "stream_options",
  "max_tokens",
  "max_completion_tokens",
  "response_format",
]);

const customModelSchema = z
  .strictObject({
    id: z.string().trim().min(1),
    name: z.string().trim().min(1).optional(),
    contextLength: z.number().int().positive(),
    maxOutputTokens: z.number().int().positive(),
  })
  .refine((model) => model.maxOutputTokens < model.contextLength, {
    message: "maxOutputTokens must be smaller than contextLength",
  });

const customProviderSchema = z.strictObject({
  name: z.string().trim().min(1).optional(),
  baseUrl: z.string().transform((value, ctx) => {
    try {
      const url = new URL(value);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      )
        throw new Error();
      url.pathname = url.pathname
        .replace(/\/+$/, "")
        .replace(/\/chat\/completions$/, "");
      return url.toString().replace(/\/+$/, "");
    } catch {
      ctx.addIssue({
        code: "custom",
        message:
          "Expected an HTTP(S) API base URL without credentials, query, or fragment",
      });
      return z.NEVER;
    }
  }),
  apiKeyEnv: z
    .string()
    .regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/)
    .optional(),
  headers: z
    .record(z.string(), z.string())
    .refine(
      (headers) =>
        !Object.keys(headers).some(
          (key) => key.toLowerCase() === "authorization",
        ),
      { message: "Use apiKeyEnv for bearer authentication" },
    )
    .optional(),
  requestBody: z
    .record(z.string(), z.json())
    .refine(
      (body) =>
        !Object.keys(body).some((key) => reservedRequestFields.has(key)),
      {
        message:
          "Request options cannot override model, messages, tools, streaming, output limits, or response format",
      },
    )
    .optional(),
  models: z
    .array(customModelSchema)
    .min(1)
    .refine(
      (models) =>
        new Set(models.map((model) => model.id)).size === models.length,
      { message: "Model IDs must be unique within a provider" },
    ),
});

const customProvidersSchema = z.record(providerIdSchema, customProviderSchema);
export type CustomProviders = z.infer<typeof customProvidersSchema>;

export function parseCustomProviders(value: unknown): CustomProviders {
  const parsed = customProvidersSchema.safeParse(value);
  if (!parsed.success) {
    // Never include supplied values: config may accidentally contain credentials.
    throw new Error(
      "Invalid customProviders configuration. Check the endpoint, credential variable, model limits, and request options.",
    );
  }
  return parsed.data;
}

export function loadCustomProviders(
  configured?: CustomProviders,
): CustomProviders {
  const raw = process.env.APEX_CUSTOM_PROVIDERS?.trim();
  let fromEnv: unknown = {};
  if (raw) {
    try {
      fromEnv = JSON.parse(raw);
    } catch {
      throw new Error(
        "APEX_CUSTOM_PROVIDERS must be a JSON object of custom provider definitions.",
      );
    }
  }
  return {
    ...parseCustomProviders(configured ?? {}),
    ...parseCustomProviders(fromEnv),
  };
}

export function parseCustomModelId(
  id: string,
): { providerId: string; modelId: string } | undefined {
  if (!id.startsWith("custom:")) return undefined;
  const match = /^custom:([a-zA-Z0-9_-]+):(.+)$/.exec(id);
  if (!match)
    throw new Error("Custom model IDs must use custom:<provider>:<model>.");
  return { providerId: match[1], modelId: match[2] };
}

export function resolveCustomModel(id: string, providers?: CustomProviders) {
  const identity = parseCustomModelId(id);
  if (!identity) throw new Error("Expected a custom model ID.");
  const configured = providers ?? loadCustomProviders();
  const provider = Object.hasOwn(configured, identity.providerId)
    ? configured[identity.providerId]
    : undefined;
  if (!provider)
    throw new Error(
      `Custom provider "${identity.providerId}" is not configured.`,
    );
  const model = provider.models.find((model) => model.id === identity.modelId);
  if (!model)
    throw new Error(
      `Model is not configured for custom provider "${identity.providerId}".`,
    );
  return { ...identity, provider, model };
}

export function resolveCustomApiKey(
  provider: CustomProviders[string],
): string | undefined {
  if (!provider.apiKeyEnv) return undefined;
  const key = process.env[provider.apiKeyEnv]?.trim();
  if (!key)
    throw new Error(
      `Set ${provider.apiKeyEnv} before using this custom provider.`,
    );
  return key;
}
