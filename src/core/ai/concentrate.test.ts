import { describe, expect, it } from "vitest";
import { getMaxOutputTokens, getModelInfo } from "./models";
import { buildAuthConfig, getProviderModel } from "./utils";

describe("Concentrate provider", () => {
  it("registers GLM 5.3 with its live context and output limits", () => {
    const info = getModelInfo("concentrate:glm-5.3");

    expect(info.provider).toBe("concentrate");
    expect(info.contextLength).toBe(1_048_576);
    expect(getMaxOutputTokens(info.id)).toBe(131_072);
  });

  it("passes the unprefixed model ID to the Responses provider", () => {
    const model = getProviderModel("concentrate:glm-5.3", {
      concentrateAPIKey: "sk-cn-test",
    }) as unknown as { modelId: string; provider: string };

    expect(model.modelId).toBe("glm-5.3");
    expect(model.provider).toBe("concentrate.responses");
  });

  it("includes the persisted key in auth config", () => {
    expect(
      buildAuthConfig({ concentrateAPIKey: "sk-cn-persisted" }),
    ).toMatchObject({ concentrateAPIKey: "sk-cn-persisted" });
  });
});
