import { describe, expect, it } from "vitest";
import type { Config } from "../config/config";
import {
  getAvailableModels,
  getDefaultModelForConfig,
  getSavedModelForConfig,
} from "./utils";

function makeConfig(overrides: Partial<Config> = {}): Config {
  return { responsibleUseAccepted: true, ...overrides };
}

describe("saved Hoonify selections", () => {
  it("preserves the provider during catalog failure instead of switching to another key", () => {
    const config = makeConfig({
      selectedModelId: "hoonify:partner-model",
      anthropicAPIKey: "other-key",
      hoonifyAPIKey: "key",
      hoonifyCatalogError: "Catalog unavailable",
    });
    const model = getSavedModelForConfig(config);
    expect(model).toEqual({
      id: "hoonify:partner-model",
      name: "partner-model",
      provider: "hoonify",
    });
    expect(getDefaultModelForConfig(config)?.provider).toBe("anthropic");
  });

  it.each([
    undefined,
    "",
    "   ",
  ])("falls back from a saved Hoonify selection without a configured key (%s)", (hoonifyAPIKey) => {
    const config = makeConfig({
      selectedModelId: "hoonify:partner-model",
      anthropicAPIKey: "other-key",
      hoonifyAPIKey,
    });
    expect(getSavedModelForConfig(config)).toBeNull();
    expect(getDefaultModelForConfig(config)?.provider).toBe("anthropic");
  });

  it("does not preserve a model missing from a successfully loaded catalog", () => {
    expect(
      getSavedModelForConfig(
        makeConfig({
          selectedModelId: "hoonify:removed-model",
          hoonifyAPIKey: "key",
          hoonifyModels: [],
        }),
      ),
    ).toBeNull();
  });

  it("uses the refreshed context window for an available saved model", () => {
    expect(
      getSavedModelForConfig(
        makeConfig({
          selectedModelId: "hoonify:partner-model",
          hoonifyAPIKey: "key",
          hoonifyModels: [
            {
              id: "partner-model",
              contextLength: 32_768,
              maxOutputTokens: 4096,
            },
          ],
        }),
      )?.contextLength,
    ).toBe(32_768);
  });
});

describe("getDefaultModelForConfig", () => {
  it("returns null when no providers are configured", () => {
    const config = makeConfig();
    expect(getDefaultModelForConfig(config)).toBeNull();
  });

  it("returns a Pensar model when Pensar is configured via accessToken", () => {
    const config = makeConfig({ accessToken: "tok_123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("pensar");
    expect(model?.id).toBe("pensar:anthropic.claude-opus-4-6-v1");
  });

  it("returns a Pensar model when Pensar is configured via pensarAPIKey", () => {
    const config = makeConfig({ pensarAPIKey: "pk_abc" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("pensar");
  });

  it("prefers Pensar over Anthropic when both are configured", () => {
    const config = makeConfig({
      accessToken: "tok_123",
      anthropicAPIKey: "sk-ant-123",
    });
    const model = getDefaultModelForConfig(config);
    expect(model?.provider).toBe("pensar");
  });

  it("returns Anthropic opus when only Anthropic is configured", () => {
    const config = makeConfig({ anthropicAPIKey: "sk-ant-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("anthropic");
    expect(model?.id).toBe("claude-opus-4-6");
  });

  it("returns OpenAI model when only OpenAI is configured", () => {
    const config = makeConfig({ openAiAPIKey: "sk-openai-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("openai");
    expect(model?.id).toBe("gpt-5.6-sol");
  });

  it("returns Google best model when only Google is configured", () => {
    const config = makeConfig({ googleAPIKey: "goog-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("google");
    expect(model?.id).toBe("gemini-3.1-pro-preview");
  });

  it("returns Google model when only Google is configured", () => {
    const config = makeConfig({ googleAPIKey: "goog-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("google");
  });

  it("returns OpenRouter model when only OpenRouter is configured", () => {
    const config = makeConfig({ openRouterAPIKey: "or-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("openrouter");
    expect(model?.id).toBe("anthropic/claude-opus-4.6");
  });

  it("returns Concentrate models when only Concentrate is configured", () => {
    const config = makeConfig({ concentrateAPIKey: "sk-cn-123" });
    const model = getDefaultModelForConfig(config);
    const available = getAvailableModels(config);

    expect(model).not.toBeNull();
    expect(model?.provider).toBe("concentrate");
    expect(model?.id).toBe("concentrate:glm-5.3");
    expect(available.length).toBeGreaterThan(1);
    expect(available.every((item) => item.provider === "concentrate")).toBe(
      true,
    );
  });

  it("prefers Anthropic over OpenAI when both are configured", () => {
    const config = makeConfig({
      anthropicAPIKey: "sk-ant-123",
      openAiAPIKey: "sk-openai-123",
    });
    const model = getDefaultModelForConfig(config);
    expect(model?.provider).toBe("anthropic");
  });

  it("prefers OpenAI over OpenRouter when both are configured", () => {
    const config = makeConfig({
      openAiAPIKey: "sk-openai-123",
      openRouterAPIKey: "or-123",
    });
    const model = getDefaultModelForConfig(config);
    expect(model?.provider).toBe("openai");
  });

  it("returns a model from available models", () => {
    const config = makeConfig({ anthropicAPIKey: "sk-ant-123" });
    const model = getDefaultModelForConfig(config);
    const available = getAvailableModels(config);
    expect(available.some((m) => m.id === model?.id)).toBe(true);
  });

  it("returns Bedrock model when only Bedrock is configured", () => {
    const config = makeConfig({ bedrockAPIKey: "bedrock-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model?.provider).toBe("bedrock");
  });
});
