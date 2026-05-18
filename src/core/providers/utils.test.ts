import { describe, expect, it } from "vitest";
import type { Config } from "../config/config";
import { getAvailableModels, getDefaultModelForConfig } from "./utils";

function makeConfig(overrides: Partial<Config> = {}): Config {
  return { responsibleUseAccepted: true, ...overrides };
}

describe("getDefaultModelForConfig", () => {
  it("returns null when no providers are configured", () => {
    const config = makeConfig();
    expect(getDefaultModelForConfig(config)).toBeNull();
  });

  it("returns a Pensar model when Pensar is configured via accessToken", () => {
    const config = makeConfig({ accessToken: "tok_123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("pensar");
    expect(model!.id).toBe("pensar:anthropic.claude-opus-4-6-v1");
  });

  it("returns a Pensar model when Pensar is configured via pensarAPIKey", () => {
    const config = makeConfig({ pensarAPIKey: "pk_abc" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("pensar");
  });

  it("prefers Pensar over Anthropic when both are configured", () => {
    const config = makeConfig({
      accessToken: "tok_123",
      anthropicAPIKey: "sk-ant-123",
    });
    const model = getDefaultModelForConfig(config);
    expect(model!.provider).toBe("pensar");
  });

  it("returns Anthropic opus when only Anthropic is configured", () => {
    const config = makeConfig({ anthropicAPIKey: "sk-ant-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("anthropic");
    expect(model!.id).toBe("claude-opus-4-6");
  });

  it("returns OpenAI model when only OpenAI is configured", () => {
    const config = makeConfig({ openAiAPIKey: "sk-openai-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("openai");
    expect(model!.id).toBe("gpt-5.2-pro");
  });

  it("returns Google best model when only Google is configured", () => {
    const config = makeConfig({ googleAPIKey: "goog-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("google");
    expect(model!.id).toBe("gemini-3.1-pro-preview");
  });

  it("returns Google model when only Google is configured", () => {
    const config = makeConfig({ googleAPIKey: "goog-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("google");
  });

  it("returns OpenRouter model when only OpenRouter is configured", () => {
    const config = makeConfig({ openRouterAPIKey: "or-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("openrouter");
    expect(model!.id).toBe("anthropic/claude-opus-4.6");
  });

  it("prefers Anthropic over OpenAI when both are configured", () => {
    const config = makeConfig({
      anthropicAPIKey: "sk-ant-123",
      openAiAPIKey: "sk-openai-123",
    });
    const model = getDefaultModelForConfig(config);
    expect(model!.provider).toBe("anthropic");
  });

  it("prefers OpenAI over OpenRouter when both are configured", () => {
    const config = makeConfig({
      openAiAPIKey: "sk-openai-123",
      openRouterAPIKey: "or-123",
    });
    const model = getDefaultModelForConfig(config);
    expect(model!.provider).toBe("openai");
  });

  it("returns a model from available models", () => {
    const config = makeConfig({ anthropicAPIKey: "sk-ant-123" });
    const model = getDefaultModelForConfig(config);
    const available = getAvailableModels(config);
    expect(available.some((m) => m.id === model!.id)).toBe(true);
  });

  it("returns Bedrock model when only Bedrock is configured", () => {
    const config = makeConfig({ bedrockAPIKey: "bedrock-123" });
    const model = getDefaultModelForConfig(config);
    expect(model).not.toBeNull();
    expect(model!.provider).toBe("bedrock");
  });
});
