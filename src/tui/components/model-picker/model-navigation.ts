import type { AIModelProvider, ModelInfo } from "../../../core/ai";

type NavigationItem = {
  type: string;
  model?: Pick<ModelInfo, "id">;
};

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
