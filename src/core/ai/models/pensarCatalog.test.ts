import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getAvailableModels,
  getSavedModelForConfig,
} from "../../providers/utils";
import { getReasoningCapabilities } from "../reasoning";
import { getMaxOutputTokens, getModelInfo, isRegisteredModel } from "./index";
import { loadPensarCatalog } from "./pensarCatalog";

afterEach(() => vi.unstubAllGlobals());
describe("Pensar gateway model discovery", () => {
  it("makes an uncurated model selectable with runtime limits and reasoning metadata", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        data: [
          {
            id: "vendor/new-reasoner",
            name: "New reasoner",
            context_length: 64000,
            top_provider: { max_completion_tokens: 8000 },
            reasoning: {
              supported_efforts: ["low", "high"],
              default_effort: "high",
            },
          },
        ],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const cfg = {
      responsibleUseAccepted: true,
      pensarAPIKey: "catalog-key",
      workspaceId: "ws-1",
      gatewayUrl: "https://gateway.example",
    };
    const pensarModels = await loadPensarCatalog(cfg);
    expect(isRegisteredModel("pensar:vendor/new-reasoner")).toBe(true);
    expect(isRegisteredModel("pensar:vendor/not-in-catalog")).toBe(false);
    expect(getAvailableModels({ ...cfg, pensarModels })).toContainEqual(
      expect.objectContaining({
        id: "pensar:vendor/new-reasoner",
        provider: "pensar",
      }),
    );
    expect(getModelInfo("pensar:vendor/new-reasoner").contextLength).toBe(
      64000,
    );
    expect(getMaxOutputTokens("pensar:vendor/new-reasoner")).toBe(8000);
    expect(
      getReasoningCapabilities("pensar:vendor/new-reasoner"),
    ).toMatchObject({ transport: "openrouter", efforts: ["low", "high"] });
    await loadPensarCatalog(cfg);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await loadPensarCatalog({ ...cfg, workspaceId: "ws-2" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
  it("preserves a saved gateway selection during catalog failure", () => {
    expect(
      getSavedModelForConfig({
        responsibleUseAccepted: true,
        pensarAPIKey: "key",
        selectedModelId: "pensar:unknown-native-model",
      }),
    ).toBeNull();
    expect(
      getSavedModelForConfig({
        responsibleUseAccepted: true,
        pensarAPIKey: "key",
        selectedModelId: "pensar:vendor/saved",
        pensarCatalogError: "Unavailable",
      }),
    ).toMatchObject({ id: "pensar:vendor/saved", provider: "pensar" });
  });
  it("does not request a catalog without Pensar authentication", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await loadPensarCatalog({})).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
