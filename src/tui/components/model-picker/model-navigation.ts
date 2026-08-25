import type { ModelInfo } from "../../../core/ai";

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
