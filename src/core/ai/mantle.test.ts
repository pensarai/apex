import { describe, expect, it } from "vitest";
import {
  isMantleResponsesModelId,
  mantleBaseUrl,
  stripMantlePrefix,
} from "./mantle";
import { getMaxOutputTokens, getModelInfo } from "./models";
import { getProviderModel } from "./utils";

describe("apex mantle helpers", () => {
  it("detects mantle routing ids and Responses-API models", () => {
    expect(isMantleResponsesModelId("openai.gpt-5.5")).toBe(true);
    expect(isMantleResponsesModelId("mantle:openai.gpt-5.5")).toBe(true);
    expect(isMantleResponsesModelId("openai.gpt-oss-120b")).toBe(false);
    expect(stripMantlePrefix("mantle:openai.gpt-5.5")).toBe("openai.gpt-5.5");
  });

  it("builds the /openai/v1 base url", () => {
    expect(mantleBaseUrl("us-east-2")).toBe(
      "https://bedrock-mantle.us-east-2.api.aws/openai/v1",
    );
  });
});

describe("mantle model registry", () => {
  it("maps the routed id to the bedrock-mantle provider", () => {
    const info = getModelInfo("mantle:openai.gpt-5.5");
    expect(info.provider).toBe("bedrock-mantle");
    expect(info.contextLength).toBe(272000);
  });

  it("uses a 128K output budget for GPT 5.5", () => {
    expect(getMaxOutputTokens("mantle:openai.gpt-5.5")).toBe(128000);
  });

  it("routes the gateway id to the pensar provider", () => {
    expect(getModelInfo("pensar:openai.gpt-5.5").provider).toBe("pensar");
  });
});

describe("getProviderModel bedrock-mantle case", () => {
  it("builds a Mantle Responses model for the routed id", () => {
    const model = getProviderModel("mantle:openai.gpt-5.5", {}) as unknown as {
      modelId: string;
      provider: string;
    };
    expect(model.modelId).toBe("openai.gpt-5.5");
    expect(model.provider).toContain("mantle");
  });
});
