import { describe, expect, it } from "vitest";
import { getModelInfo } from "./models";
import { buildAuthConfig, getProviderModel } from "./utils";

describe("Concentrate provider", () => {
  it("registers namespaced model IDs", () => {
    const info = getModelInfo("concentrate:claude-opus-4-6");

    expect(info.provider).toBe("concentrate");
    expect(info.contextLength).toBe(200000);
  });

  it("passes the unprefixed model ID to the compatible provider", () => {
    const model = getProviderModel("concentrate:gpt-5.4", {
      concentrateAPIKey: "sk-cn-test",
    }) as unknown as { modelId: string; provider: string };

    expect(model.modelId).toBe("gpt-5.4");
    expect(model.provider).toBe("concentrate.chat");
  });

  it("includes the persisted key in auth config", () => {
    expect(
      buildAuthConfig({ concentrateAPIKey: "sk-cn-persisted" }),
    ).toMatchObject({ concentrateAPIKey: "sk-cn-persisted" });
  });
});
