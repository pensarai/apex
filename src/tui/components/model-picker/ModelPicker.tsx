import { useState, useEffect, useMemo, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import type { ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import type { Config } from "../../../core/config/config";
import { useTheme } from "../../theme";

const providerNames: Record<string, string> = {
  anthropic: "Claude",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
  pensar: "Pensar",
  local: "Local LLM",
};

const providerOrder = [
  "pensar",
  "anthropic",
  "openai",
  "openrouter",
  "bedrock",
  "local",
];

type NavigationItem =
  | { type: "provider"; provider: string }
  | { type: "model"; model: ModelInfo }
  | { type: "local-input"; field: LocalInputField };

type LocalInputField = "url" | "model";

export interface ModelPickerProps {
  config: Config | null;
  selectedModel: ModelInfo;
  onSelectModel: (model: ModelInfo) => void;
  onConfirm?: () => void;
  onConfigUpdate?: (update: Partial<Config>) => Promise<void>;
  focused?: boolean;
  isModelUserSelected?: boolean;
}

export function ModelPicker({
  config,
  selectedModel,
  onSelectModel,
  onConfirm,
  onConfigUpdate,
  focused = true,
  isModelUserSelected = false,
}: ModelPickerProps) {
  const { colors } = useTheme();
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );
  const [focusedIndex, setFocusedIndex] = useState(0);

  const [localUrl, setLocalUrl] = useState(config?.localModelUrl ?? "");
  const [localModelName, setLocalModelName] = useState(
    config?.localModelName ?? "",
  );
  const [editingLocalField, setEditingLocalField] =
    useState<LocalInputField | null>(null);

  useEffect(() => {
    setLocalUrl(config?.localModelUrl ?? "");
    setLocalModelName(config?.localModelName ?? "");
  }, [config?.localModelUrl, config?.localModelName]);

  // Load models when config changes
  useEffect(() => {
    if (config) {
      const models = getAvailableModels(config);
      setAvailableModels(models);
      // Auto-expand provider of current model
      if (models.length > 0) {
        const currentModel =
          models.find((m) => m.id === selectedModel.id) || models[0];
        if (currentModel) {
          setExpandedProviders(new Set([currentModel.provider]));
        }
      }
    }
  }, [config, selectedModel.id]);

  // Group models by provider and filter by search
  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    const query = searchQuery.toLowerCase().trim();

    for (const m of availableModels) {
      // Fuzzy match: check if query matches model name or id
      if (
        query &&
        !m.name.toLowerCase().includes(query) &&
        !m.id.toLowerCase().includes(query)
      ) {
        continue;
      }
      if (!groups[m.provider]) {
        groups[m.provider] = [];
      }
      groups[m.provider].push(m);
    }
    return groups;
  }, [availableModels, searchQuery]);

  // Flat navigation list: provider headers + expanded models
  const navigationItems = useMemo(() => {
    const items: NavigationItem[] = [];
    for (const provider of providerOrder) {
      if (provider === "local") {
        items.push({ type: "provider", provider: "local" });
        if (expandedProviders.has("local")) {
          items.push({ type: "local-input", field: "url" });
          items.push({ type: "local-input", field: "model" });
          const localModels = groupedModels["local"];
          if (localModels) {
            for (const m of localModels) {
              items.push({ type: "model", model: m });
            }
          }
        }
        continue;
      }
      const models = groupedModels[provider];
      if (!models || models.length === 0) continue;
      items.push({ type: "provider", provider });
      if (expandedProviders.has(provider)) {
        for (const m of models) {
          items.push({ type: "model", model: m });
        }
      }
    }
    return items;
  }, [groupedModels, expandedProviders]);

  // Sync focusedIndex when selected model changes (e.g. on initial load)
  useEffect(() => {
    const idx = navigationItems.findIndex(
      (item) => item.type === "model" && item.model.id === selectedModel.id,
    );
    if (idx !== -1) {
      setFocusedIndex(idx);
    }
  }, [selectedModel.id, navigationItems]);

  // Clamp focusedIndex when navigation items change
  useEffect(() => {
    setFocusedIndex((prev) =>
      Math.min(prev, Math.max(0, navigationItems.length - 1)),
    );
  }, [navigationItems.length]);

  const commitLocalConfig = useCallback(
    (url: string, modelName: string) => {
      if (!onConfigUpdate) return;
      const update: Partial<Config> = {
        localModelUrl: url || null,
        localModelName: modelName || null,
      };
      onConfigUpdate(update);
    },
    [onConfigUpdate],
  );

  const finishEditing = useCallback(() => {
    setEditingLocalField(null);
    commitLocalConfig(localUrl, localModelName);
  }, [localUrl, localModelName, commitLocalConfig]);

  // Handle keyboard navigation (most keys disabled while editing local input)
  const handleKeyboard = useCallback(
    (key: {
      name?: string;
      sequence?: string;
      ctrl?: boolean;
      shift?: boolean;
      meta?: boolean;
    }) => {
      if (!focused) return false;

      if (editingLocalField) {
        if (key.name === "escape") {
          finishEditing();
          return true;
        }
        return false;
      }

      if (navigationItems.length === 0) return false;

      // Up/Down - navigate through items
      if (key.name === "up" || key.name === "down") {
        const newIndex =
          key.name === "up"
            ? Math.max(0, focusedIndex - 1)
            : Math.min(navigationItems.length - 1, focusedIndex + 1);
        setFocusedIndex(newIndex);
        const item = navigationItems[newIndex];
        if (item && item.type === "model") {
          onSelectModel(item.model);
        }
        return true;
      }

      // Backspace - remove last char from search
      if (key.name === "backspace") {
        setSearchQuery((prev) => prev.slice(0, -1));
        return true;
      }

      // Escape - clear search (if there is one)
      if (key.name === "escape" && searchQuery) {
        setSearchQuery("");
        return true;
      }

      // Enter - confirm model selection, toggle provider, or start editing local input
      if (key.name === "return") {
        const currentItem = navigationItems[focusedIndex];
        if (!currentItem) return false;

        if (currentItem.type === "local-input") {
          setEditingLocalField(currentItem.field);
          return true;
        }

        if (currentItem.type === "provider") {
          const targetProvider = currentItem.provider;
          setExpandedProviders((prev) => {
            const next = new Set(prev);
            if (next.has(targetProvider)) {
              next.delete(targetProvider);
            } else {
              next.add(targetProvider);
            }
            return next;
          });
        } else {
          onConfirm?.();
        }
        return true;
      }

      // Left/Right - collapse/expand provider
      if (key.name === "left" || key.name === "right") {
        const currentItem = navigationItems[focusedIndex];
        if (!currentItem) return false;

        const targetProvider =
          currentItem.type === "provider"
            ? currentItem.provider
            : currentItem.type === "model"
              ? currentItem.model.provider
              : "local";

        if (key.name === "left") {
          setExpandedProviders((prev) => {
            const next = new Set(prev);
            next.delete(targetProvider);
            return next;
          });
          const headerIdx = navigationItems.findIndex(
            (item) =>
              item.type === "provider" && item.provider === targetProvider,
          );
          if (headerIdx !== -1) {
            setFocusedIndex(headerIdx);
          }
        } else {
          setExpandedProviders((prev) => new Set([...prev, targetProvider]));
        }
        return true;
      }

      // Printable character - add to search
      if (
        key.sequence &&
        key.sequence.length === 1 &&
        /[a-zA-Z0-9\-_.]/.test(key.sequence)
      ) {
        setSearchQuery((prev) => prev + key.sequence);
        if (!searchQuery) {
          setExpandedProviders(new Set(providerOrder));
        }
        return true;
      }

      return false;
    },
    [
      focused,
      editingLocalField,
      finishEditing,
      navigationItems,
      focusedIndex,
      onSelectModel,
      onConfirm,
      searchQuery,
    ],
  );

  useKeyboard((key) => {
    handleKeyboard(key);
  });

  return (
    <box flexDirection="column" gap={0}>
      {/* Search indicator */}
      {searchQuery ? (
        <text fg={colors.text}>Search: {searchQuery}_</text>
      ) : (
        <text fg={colors.textMuted}>Type to search models...</text>
      )}

      {/* Provider groups */}
      {providerOrder.map((provider) => {
        const isExpanded = expandedProviders.has(provider);
        const providerName = providerNames[provider] || provider;
        const isProviderFocused =
          navigationItems[focusedIndex]?.type === "provider" &&
          (
            navigationItems[focusedIndex] as {
              type: "provider";
              provider: string;
            }
          ).provider === provider;

        if (provider === "local") {
          const localModels = groupedModels["local"];
          const modelCount = localModels?.length ?? 0;
          return (
            <box key="local" flexDirection="column" gap={0}>
              <text
                fg={
                  isProviderFocused
                    ? colors.primary
                    : isExpanded
                      ? colors.text
                      : colors.textMuted
                }
              >
                {isProviderFocused ? "❯" : isExpanded ? "▾" : "▸"}{" "}
                {providerName}
                {modelCount > 0 ? ` (${modelCount})` : ""}
              </text>

              {isExpanded && (
                <box flexDirection="column" gap={0} paddingLeft={2}>
                  {/* URL input */}
                  {(() => {
                    const isUrlFocused =
                      navigationItems[focusedIndex]?.type === "local-input" &&
                      (
                        navigationItems[focusedIndex] as {
                          type: "local-input";
                          field: LocalInputField;
                        }
                      ).field === "url";
                    const isUrlEditing = editingLocalField === "url";
                    if (isUrlEditing) {
                      return (
                        <box flexDirection="row">
                          <text fg={colors.primary}> URL: </text>
                          <input
                            focused={true}
                            value={localUrl}
                            backgroundColor="transparent"
                            cursorColor={colors.textMuted}
                            onInput={(v) =>
                              setLocalUrl(typeof v === "string" ? v : "")
                            }
                            onPaste={(event) => {
                              const cleaned = String(event.text).replace(
                                /\r?\n/g,
                                "",
                              );
                              setLocalUrl((prev) => `${prev}${cleaned}`);
                            }}
                            onSubmit={finishEditing}
                          />
                        </box>
                      );
                    }
                    return (
                      <text
                        fg={isUrlFocused ? colors.primary : colors.textMuted}
                      >
                        {`  URL: ${localUrl || "(press Enter to set)"}`}
                      </text>
                    );
                  })()}

                  {/* Model name input */}
                  {(() => {
                    const isModelFocused =
                      navigationItems[focusedIndex]?.type === "local-input" &&
                      (
                        navigationItems[focusedIndex] as {
                          type: "local-input";
                          field: LocalInputField;
                        }
                      ).field === "model";
                    const isModelEditing = editingLocalField === "model";
                    if (isModelEditing) {
                      return (
                        <box flexDirection="row">
                          <text fg={colors.primary}> Model: </text>
                          <input
                            focused={true}
                            value={localModelName}
                            backgroundColor="transparent"
                            cursorColor={colors.textMuted}
                            onInput={(v) =>
                              setLocalModelName(typeof v === "string" ? v : "")
                            }
                            onPaste={(event) => {
                              const cleaned = String(event.text).replace(
                                /\r?\n/g,
                                "",
                              );
                              setLocalModelName((prev) => `${prev}${cleaned}`);
                            }}
                            onSubmit={finishEditing}
                          />
                        </box>
                      );
                    }
                    return (
                      <text
                        fg={isModelFocused ? colors.primary : colors.textMuted}
                      >
                        {`  Model: ${localModelName || "(press Enter to set)"}`}
                      </text>
                    );
                  })()}

                  {/* Local models (after config is set) */}
                  {localModels?.map((m) => {
                    const isSelected = m.id === selectedModel.id;
                    const isFocused =
                      navigationItems[focusedIndex]?.type === "model" &&
                      (
                        navigationItems[focusedIndex] as {
                          type: "model";
                          model: ModelInfo;
                        }
                      ).model.id === m.id;
                    return (
                      <text
                        key={m.id}
                        fg={isFocused ? colors.primary : colors.textMuted}
                      >
                        {isSelected ? "●" : "○"} {m.name}
                      </text>
                    );
                  })}
                </box>
              )}
            </box>
          );
        }

        const models = groupedModels[provider];
        if (!models || models.length === 0) return null;

        return (
          <box key={provider} flexDirection="column" gap={0}>
            <text
              fg={
                isProviderFocused
                  ? colors.primary
                  : isExpanded
                    ? colors.text
                    : colors.textMuted
              }
            >
              {isProviderFocused ? "❯" : isExpanded ? "▾" : "▸"} {providerName}{" "}
              ({models.length})
            </text>

            {isExpanded && (
              <box flexDirection="column" gap={0} paddingLeft={2}>
                {models.map((m) => {
                  const isSelected = m.id === selectedModel.id;
                  const isFocused =
                    navigationItems[focusedIndex]?.type === "model" &&
                    (
                      navigationItems[focusedIndex] as {
                        type: "model";
                        model: ModelInfo;
                      }
                    ).model.id === m.id;
                  const isDefault =
                    m.id === "claude-haiku-4-5" || m.id === "gpt-4o-mini";
                  return (
                    <text
                      key={m.id}
                      fg={isFocused ? colors.primary : colors.textMuted}
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

      {/* Help text */}
      <text fg={colors.textMuted}>
        {editingLocalField
          ? "Type or paste | Enter/Esc to confirm"
          : "↑/↓ navigate | ←/→ collapse/expand | Type to search"}
      </text>
    </box>
  );
}

export default ModelPicker;
