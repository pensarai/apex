import { useState, useEffect, useMemo } from "react";
import { useConfig } from "../../../context/config";
import { useAgent } from "../../../context/agent";
import { useTheme } from "../../../theme";
import type { ModelInfo } from "../../../../core/ai";
import { getAvailableModels } from "../../../../core/providers/utils";

/** Provider display names */
export const PROVIDER_NAMES: Record<string, string> = {
  anthropic: "Claude",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
};

/** Ordered list of provider keys for display */
export const PROVIDER_ORDER = ["anthropic", "openai", "openrouter", "bedrock"];

interface ModelPickerSectionProps {
  expanded: boolean;
  /** Model picker hook instance — provides shared state and handlers */
  picker: ReturnType<typeof useModelPicker>;
}

/**
 * Full model picker with provider groups, search, and keyboard navigation.
 * Used by web-wizard in the configure step.
 *
 * This component renders from the state owned by the useModelPicker hook,
 * which is passed in via the `picker` prop. The parent wizard creates the hook
 * and passes it here so keyboard handling and UI share the same state.
 */
export function ModelPickerSection({
  expanded,
  picker,
}: ModelPickerSectionProps) {
  const { colors } = useTheme();
  const { isModelUserSelected } = useAgent();

  return (
    <box flexDirection="column" gap={1}>
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={expanded ? colors.text : colors.textMuted}>AI Model</span>
        <span fg={colors.textMuted}> ({picker.model.name})</span>
        <span fg={colors.textMuted}>
          {" "}
          [{isModelUserSelected ? "user" : "default"}]
        </span>
      </text>
      {expanded && (
        <box flexDirection="column" gap={0} paddingLeft={2}>
          {picker.modelSearchQuery ? (
            <text fg={colors.text}>Search: {picker.modelSearchQuery}_</text>
          ) : (
            <text fg={colors.textMuted}>Type to search models...</text>
          )}

          {PROVIDER_ORDER.map((provider) => {
            const models = picker.groupedModels[provider];
            if (!models || models.length === 0) return null;

            const isExpanded = picker.expandedProviders.has(provider);
            const providerName = PROVIDER_NAMES[provider] || provider;

            return (
              <box key={provider} flexDirection="column" gap={0}>
                <text fg={isExpanded ? colors.text : colors.textMuted}>
                  {isExpanded ? "▾" : "▸"} {providerName} ({models.length})
                </text>
                {isExpanded && (
                  <box flexDirection="column" gap={0} paddingLeft={2}>
                    {models.map((m) => {
                      const isSelected = m.id === picker.model.id;
                      const isDefault =
                        m.id === "claude-haiku-4-5" || m.id === "gpt-4o-mini";
                      return (
                        <text
                          key={m.id}
                          fg={isSelected ? colors.primary : colors.textMuted}
                        >
                          {isSelected ? "●" : "○"} {m.name}
                          {isDefault && !isModelUserSelected && isSelected
                            ? " [default]"
                            : ""}
                        </text>
                      );
                    })}
                  </box>
                )}
              </box>
            );
          })}

          <text fg={colors.textMuted}>
            ↑/↓ select • Type to search • ←/→ collapse/expand
          </text>
        </box>
      )}
    </box>
  );
}

/**
 * Hook that provides model picker state and keyboard handlers.
 * Returns handlers that the parent wizard's keyboard handler can delegate to.
 */
export function useModelPicker(initialModel?: string) {
  const config = useConfig();
  const { model, setModel } = useAgent();

  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [modelSearchQuery, setModelSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );

  useEffect(() => {
    if (config.data) {
      const models = getAvailableModels(config.data);
      setAvailableModels(models);

      if (initialModel) {
        const targetModel = models.find((m) => m.id === initialModel);
        if (targetModel) {
          setModel(targetModel);
          setExpandedProviders(new Set([targetModel.provider]));
          return;
        }
      }

      if (models.length > 0) {
        const currentModel = models.find((m) => m.id === model.id) || models[0];
        if (currentModel) {
          setExpandedProviders(new Set([currentModel.provider]));
        }
      }
    }
  }, [config.data, model.id, initialModel]);

  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    const query = modelSearchQuery.toLowerCase().trim();
    for (const m of availableModels) {
      if (
        query &&
        !m.name.toLowerCase().includes(query) &&
        !m.id.toLowerCase().includes(query)
      ) {
        continue;
      }
      if (!groups[m.provider]) groups[m.provider] = [];
      groups[m.provider].push(m);
    }
    return groups;
  }, [availableModels, modelSearchQuery]);

  const visibleModels = useMemo(() => {
    const result: ModelInfo[] = [];
    for (const provider of PROVIDER_ORDER) {
      const models = groupedModels[provider];
      if (!models || models.length === 0) continue;
      if (expandedProviders.has(provider)) {
        result.push(...models);
      }
    }
    return result;
  }, [groupedModels, expandedProviders]);

  /** Navigate model selection up/down */
  const navigateModel = (direction: "up" | "down") => {
    if (visibleModels.length === 0) return;
    const currentIdx = visibleModels.findIndex((m) => m.id === model.id);
    const newIdx =
      direction === "up"
        ? Math.max(0, currentIdx - 1)
        : Math.min(visibleModels.length - 1, currentIdx + 1);
    const newModel = visibleModels[newIdx];
    if (newModel) setModel(newModel);
  };

  /** Simple left/right model cycling (for operator-wizard inline picker) */
  const cycleModel = (delta: number) => {
    if (visibleModels.length === 0) return;
    const currentIdx = visibleModels.findIndex((m) => m.id === model.id);
    const newIdx = Math.max(
      0,
      Math.min(visibleModels.length - 1, currentIdx + delta),
    );
    const newModel = visibleModels[newIdx];
    if (newModel) setModel(newModel);
  };

  /** Handle typing into model search */
  const handleSearchChar = (char: string) => {
    if (/[a-zA-Z0-9\-_.]/.test(char)) {
      setModelSearchQuery((prev) => {
        if (!prev) setExpandedProviders(new Set(PROVIDER_ORDER));
        return prev + char;
      });
    }
  };

  const handleSearchBackspace = () => {
    setModelSearchQuery((prev) => prev.slice(0, -1));
  };

  const clearSearch = () => {
    setModelSearchQuery("");
  };

  /** Toggle provider expansion */
  const toggleProvider = (direction: "left" | "right") => {
    const currentProvider = model.provider;
    if (direction === "left") {
      setExpandedProviders((prev) => {
        const next = new Set(prev);
        next.delete(currentProvider);
        return next;
      });
    } else {
      setExpandedProviders((prev) => new Set([...prev, currentProvider]));
    }
  };

  /** Cycle to next unexpanded provider. Returns true if one was expanded, false if all already expanded. */
  const expandNextProvider = (): boolean => {
    const available = PROVIDER_ORDER.filter(
      (p) => (groupedModels[p]?.length ?? 0) > 0,
    );
    const next = available.find((p) => !expandedProviders.has(p));
    if (next) {
      setExpandedProviders((prev) => new Set([...prev, next]));
      return true;
    }
    return false;
  };

  return {
    model,
    visibleModels,
    groupedModels,
    expandedProviders,
    modelSearchQuery,
    navigateModel,
    cycleModel,
    handleSearchChar,
    handleSearchBackspace,
    clearSearch,
    toggleProvider,
    expandNextProvider,
  };
}
