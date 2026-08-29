import { describe, expect, it } from "vitest";
import type { ModelInfo } from "../../../core/ai";
import { filterModels } from "./model-search";

const models: ModelInfo[] = [
  {
    id: "claude-opus-4-6",
    name: "Claude Opus 4.6",
    provider: "anthropic",
  },
  {
    id: "anthropic/claude-opus-4.6",
    name: "Claude Opus 4.6",
    provider: "openrouter",
  },
  {
    id: "moonshotai/kimi-k3",
    name: "Kimi K3",
    provider: "openrouter",
  },
  {
    id: "z-ai/glm-5.3",
    name: "GLM 5.3",
    provider: "openrouter",
  },
  {
    id: "gpt-5.6-sol",
    name: "GPT-5.6-sol",
    provider: "openai",
  },
];

describe("filterModels", () => {
  it("matches a model family", () => {
    expect(filterModels(models, "kimi")).toEqual([models[2]]);
  });

  it("matches a model name across punctuation", () => {
    expect(filterModels(models, "opus 4.6")).toEqual([models[0], models[1]]);
    expect(filterModels(models, "glm-5.3")).toEqual([models[3]]);
  });

  it("matches provider names", () => {
    expect(filterModels(models, "open router")).toEqual([
      models[1],
      models[2],
      models[3],
    ]);
  });

  it("combines family and provider terms", () => {
    expect(filterModels(models, "claude openrouter")).toEqual([models[1]]);
  });

  it("matches model IDs case-insensitively", () => {
    expect(filterModels(models, "GPT-5.6-SOL")).toEqual([models[4]]);
  });

  it("returns every model for an empty query", () => {
    expect(filterModels(models, "   ")).toBe(models);
  });
});
