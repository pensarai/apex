import type { AIModelProvider, ModelInfo } from "../../../core/ai";

type NavigationItem = {
  type: string;
  model?: Pick<ModelInfo, "id">;
};

type ModelIdentity = Pick<ModelInfo, "id" | "provider">;

export function findSelectedModelIndex(
  navigationItems: readonly NavigationItem[],
  selectedModelId: string,
): number {
  return navigationItems.findIndex(
    (item) =>
      (item.type === "model" || item.type === "recent-model") &&
      item.model?.id === selectedModelId,
  );
}

export function retainAvailableProviders(
  expandedProviders: Set<AIModelProvider>,
  availableProviders: ReadonlySet<AIModelProvider>,
): Set<AIModelProvider> {
  const retainedProviders = new Set(
    [...expandedProviders].filter((provider) =>
      availableProviders.has(provider),
    ),
  );

  return retainedProviders.size === expandedProviders.size
    ? expandedProviders
    : retainedProviders;
}

export function getSelectedModelRevealKey({
  availableModels,
  selectedModel,
  lastRevealedSelectedModelKey,
}: {
  availableModels: readonly ModelIdentity[];
  selectedModel: ModelIdentity;
  lastRevealedSelectedModelKey: string | null;
}): string | null {
  const selectedModelKey = `${selectedModel.provider}:${selectedModel.id}`;
  if (lastRevealedSelectedModelKey === selectedModelKey) return null;

  const selectedModelIsAvailable = availableModels.some(
    (model) =>
      model.id === selectedModel.id &&
      model.provider === selectedModel.provider,
  );
  return selectedModelIsAvailable ? selectedModelKey : null;
}
