import { afterEach, describe, expect, it, vi } from "vitest";
import { filterModels } from "../../tui/components/model-picker/model-search";
import { resolveExplicitCliModel } from "../cli/model";
import {
  getAvailableModels,
  hasAnyProviderConfigured,
} from "../providers/utils";
import {
  loadCustomProviders,
  parseCustomProviders,
  resolveCustomModel,
} from "./customProviders";

const providers = {
  research: {
    name: "Research endpoint",
    baseUrl: "https://inference.example/v1",
    apiKeyEnv: "APEX_TEST_CUSTOM_KEY",
    models: [
      { id: "glm-5.3", contextLength: 200_000, maxOutputTokens: 32_000 },
    ],
  },
};

afterEach(() => vi.unstubAllEnvs());

describe("custom provider configuration", () => {
  it("normalizes a pasted completion URL without duplicating its path", () => {
    const parsed = parseCustomProviders({
      research: {
        ...providers.research,
        baseUrl: "https://inference.example/api/paas/v4/chat/completions/",
      },
    });
    expect(parsed.research.baseUrl).toBe(
      "https://inference.example/api/paas/v4",
    );
  });

  it.each([
    { baseUrl: "file:///tmp/model" },
    { baseUrl: "https://token:secret@inference.example/v1" },
    { baseUrl: "https://inference.example/v1?key=secret" },
    { apiKey: "secret-value" },
    { headers: { Authorization: "Bearer secret-value" } },
    { requestBody: { messages: [] } },
    { requestBody: { stream: false } },
    { requestBody: { max_tokens: 1 } },
    { models: [{ id: "glm-5.3", contextLength: 100, maxOutputTokens: 100 }] },
    { models: [providers.research.models[0], providers.research.models[0]] },
  ])("rejects invalid config without echoing supplied values: %j", (override) => {
    expect(() =>
      parseCustomProviders({
        research: { ...providers.research, ...override },
      }),
    ).toThrow("Invalid customProviders configuration.");
  });

  it("overrides entire provider entries from the worker environment", () => {
    vi.stubEnv(
      "APEX_CUSTOM_PROVIDERS",
      JSON.stringify({
        research: {
          ...providers.research,
          baseUrl: "http://localhost:9000/v1",
        },
      }),
    );
    expect(loadCustomProviders(providers).research.baseUrl).toBe(
      "http://localhost:9000/v1",
    );
    vi.stubEnv("APEX_CUSTOM_PROVIDERS", "malformed-secret-value");
    expect(() => loadCustomProviders()).toThrow(
      "APEX_CUSTOM_PROVIDERS must be a JSON object",
    );
  });

  it("lists distinct models from multiple endpoints in the operator picker", () => {
    const cfg = {
      responsibleUseAccepted: true,
      customProviders: {
        ...providers,
        other: { ...providers.research, name: "Other endpoint" },
      },
    };
    expect(hasAnyProviderConfigured(cfg)).toBe(true);
    const models = getAvailableModels(cfg);
    expect(models.map((model) => model.id)).toEqual([
      "custom:research:glm-5.3",
      "custom:other:glm-5.3",
    ]);
    expect(filterModels(models, "research glm 5.3")).toEqual([models[0]]);
    expect(models[0].provider).toBe("custom");
  });

  it("resolves the CLI provider separately from the upstream model", () => {
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "test-secret");
    expect(
      resolveExplicitCliModel({
        model: "glm-5.3",
        provider: "research",
        customProviders: providers,
      }),
    ).toBe("custom:research:glm-5.3");
    expect(
      resolveExplicitCliModel({
        model: "claude-opus-4-6",
        customProviders: providers,
      }),
    ).toBe("claude-opus-4-6");
  });

  it("fails before a headless job starts when the provider, model, or key is missing", () => {
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "");
    expect(() =>
      resolveExplicitCliModel({
        model: "glm-5.3",
        provider: "research",
        customProviders: providers,
      }),
    ).toThrow("APEX_TEST_CUSTOM_KEY");
    expect(() =>
      resolveCustomModel("custom:missing:glm-5.3", providers),
    ).toThrow("not configured");
    expect(() =>
      resolveCustomModel("custom:research:unknown", providers),
    ).toThrow("not configured");
    expect(() => resolveExplicitCliModel({ provider: "research" })).toThrow(
      "requires --model",
    );
    expect(() => resolveCustomModel("custom:research:", providers)).toThrow(
      "must use",
    );
  });

  it("retains slashes and colons in upstream model IDs", () => {
    const customProviders = {
      research: {
        ...providers.research,
        models: [{ ...providers.research.models[0], id: "org/model:revision" }],
      },
    };
    expect(
      resolveCustomModel("custom:research:org/model:revision", customProviders)
        .modelId,
    ).toBe("org/model:revision");
  });
});
