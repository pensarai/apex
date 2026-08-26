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
      model("gpt-4o-2024-05-13", "openai"),
      model("gpt-5.6-sol", "openai"),
      model("gemini-2.0-flash", "google"),
      model("gemini-3.1-pro-preview", "google"),
    ];

    expect(getVisiblePickerModels(models)).toEqual([
      models[1],
      models[4],
      models[6],
    ]);
  });

  it("keeps a hidden model visible while it is the selected model", () => {
    const models = [
      model("gpt-3.5-turbo", "openai"),
      model("gpt-5.6-sol", "openai"),
    ];

    expect(
      getVisiblePickerModels(models, {
        id: "gpt-3.5-turbo",
        provider: "openai",
      }),
    ).toEqual(models);
  });

  it("does not exempt a hidden model selected on a different provider", () => {
    const models = [
      model("gpt-3.5-turbo", "openai"),
      model("gpt-3.5-turbo", "local"),
    ];

    expect(
      getVisiblePickerModels(models, {
        id: "gpt-3.5-turbo",
        provider: "local",
      }),
    ).toEqual([models[1]]);
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
