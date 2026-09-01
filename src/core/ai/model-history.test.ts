import { describe, expect, it } from "vitest";
import type { ModelInfo } from "./ai";
import {
  addRecentModelId,
  getRecentModels,
  MAX_RECENT_MODELS,
} from "./model-history";

const models: ModelInfo[] = [
  { id: "model-a", name: "Model A", provider: "anthropic" },
  { id: "model-b", name: "Model B", provider: "openai" },
  { id: "model-c", name: "Model C", provider: "google" },
];

describe("addRecentModelId", () => {
  it("puts the latest model first without duplicates", () => {
    expect(
      addRecentModelId(["model-a", "model-a", "model-b"], "model-b"),
    ).toEqual(["model-b", "model-a"]);
  });

  it("keeps at most five models", () => {
    const recent = addRecentModelId(
      ["model-a", "model-b", "model-c", "model-d", "model-e"],
      "model-f",
    );

    expect(recent).toHaveLength(MAX_RECENT_MODELS);
    expect(recent).toEqual([
      "model-f",
      "model-a",
      "model-b",
      "model-c",
      "model-d",
    ]);
  });
});

describe("getRecentModels", () => {
  it("preserves history order and omits unavailable models", () => {
    expect(getRecentModels(models, ["model-c", "missing", "model-a"])).toEqual([
      models[2],
      models[0],
    ]);
  });

  it("deduplicates legacy history entries", () => {
    expect(getRecentModels(models, ["model-b", "model-b", "model-a"])).toEqual([
      models[1],
      models[0],
    ]);
  });
});
