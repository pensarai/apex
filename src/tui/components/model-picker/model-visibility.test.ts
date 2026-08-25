import { describe, expect, it } from "vitest";
import type { AIModelProvider, ModelInfo } from "../../../core/ai";
import { getVisiblePickerModels } from "./model-visibility";

function model(id: string, provider: AIModelProvider): ModelInfo {
  return { id, name: id, provider };
}

describe("getVisiblePickerModels", () => {
  it("hides deprecated direct-provider models", () => {
    const models = [
      model("claude-3-haiku-20240307", "anthropic"),
      model("claude-opus-4-8", "anthropic"),
      model("gpt-3.5-turbo", "openai"),
      model("gpt-5.6-sol", "openai"),
      model("gemini-2.0-flash", "google"),
      model("gemini-3.1-pro-preview", "google"),
    ];

    expect(getVisiblePickerModels(models)).toEqual([
      models[1],
      models[3],
      models[5],
    ]);
  });

  it("does not apply one provider's lifecycle to another provider", () => {
    const models = [
      model("gpt-3.5-turbo", "local"),
      model("openai/gpt-3.5-turbo", "openrouter"),
      model("anthropic.claude-3-haiku-20240307-v1:0", "bedrock"),
    ];

    expect(getVisiblePickerModels(models)).toEqual(models);
  });
});
