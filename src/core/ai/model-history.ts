import type { ModelInfo } from "./ai";

export const MAX_RECENT_MODELS = 5;

export function addRecentModelId(
  recentModelIds: readonly string[],
  modelId: string,
): string[] {
  const nextRecentModelIds: string[] = [];

  for (const id of [modelId, ...recentModelIds]) {
    if (nextRecentModelIds.includes(id)) continue;
    nextRecentModelIds.push(id);
    if (nextRecentModelIds.length === MAX_RECENT_MODELS) break;
  }

  return nextRecentModelIds;
}

export function getRecentModels(
  availableModels: readonly ModelInfo[],
  recentModelIds: readonly string[],
): ModelInfo[] {
  const modelsById = new Map(availableModels.map((model) => [model.id, model]));
  const seen = new Set<string>();
  const recentModels: ModelInfo[] = [];

  for (const id of recentModelIds) {
    const model = modelsById.get(id);
    if (!model || seen.has(id)) continue;

    seen.add(id);
    recentModels.push(model);
    if (recentModels.length === MAX_RECENT_MODELS) break;
  }

  return recentModels;
}
