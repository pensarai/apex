import { describe, expect, it } from "vitest";
import type { AIModelProvider } from "../../../core/ai";
import {
  findSelectedModelIndex,
  getSelectedModelRevealKey,
  retainAvailableProviders,
} from "./model-navigation";

describe("findSelectedModelIndex", () => {
  it("focuses the selected recent model instead of the first recent model", () => {
    expect(
      findSelectedModelIndex(
        [
          { type: "recent-model", model: { id: "model-a" } },
          { type: "recent-model", model: { id: "model-b" } },
          { type: "provider" },
          { type: "model", model: { id: "model-b" } },
        ],
        "model-b",
      ),
    ).toBe(1);
  });

  it("finds the selected model outside recent history", () => {
    expect(
      findSelectedModelIndex(
        [
          { type: "recent-model", model: { id: "model-a" } },
          { type: "provider" },
          { type: "model", model: { id: "model-b" } },
        ],
        "model-b",
      ),
    ).toBe(2);
  });

  it("returns -1 when the selected model is not visible", () => {
    expect(
      findSelectedModelIndex(
        [
          { type: "recent-model", model: { id: "model-a" } },
          { type: "provider" },
        ],
        "model-b",
      ),
    ).toBe(-1);
  });
});

describe("retainAvailableProviders", () => {
  it("keeps an available provider collapsed after a model refresh", () => {
    const collapsedProviders = new Set<AIModelProvider>();

    expect(
      retainAvailableProviders(
        collapsedProviders,
        new Set<AIModelProvider>(["anthropic"]),
      ),
    ).toBe(collapsedProviders);
  });

  it("removes providers that are no longer available", () => {
    expect(
      retainAvailableProviders(
        new Set<AIModelProvider>(["anthropic", "openai"]),
        new Set<AIModelProvider>(["openai"]),
      ),
    ).toEqual(new Set<AIModelProvider>(["openai"]));
  });
});

describe("getSelectedModelRevealKey", () => {
  it("waits for availability and reveals each selection only once", () => {
    const selectedModel = {
      id: "model-b" as const,
      provider: "anthropic" as const,
    };

    expect(
      getSelectedModelRevealKey({
        availableModels: [],
        selectedModel,
        lastRevealedSelectedModelKey: null,
      }),
    ).toBeNull();

    const selectedModelKey = getSelectedModelRevealKey({
      availableModels: [selectedModel],
      selectedModel,
      lastRevealedSelectedModelKey: null,
    });
    expect(selectedModelKey).toBe("anthropic:model-b");

    expect(
      getSelectedModelRevealKey({
        availableModels: [{ ...selectedModel }],
        selectedModel,
        lastRevealedSelectedModelKey: selectedModelKey,
      }),
    ).toBeNull();
  });
});
