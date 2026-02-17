import { useState, useEffect, useMemo, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import type { ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import type { Config } from "../../../core/config/config";

const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

const providerNames: Record<string, string> = {
  anthropic: "Claude",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
};

const providerOrder = ["anthropic", "openai", "openrouter", "bedrock"];

type NavigationItem =
  | { type: "provider"; provider: string }
  | { type: "model"; model: ModelInfo };

export interface ModelPickerProps {
  config: Config | null;
  selectedModel: ModelInfo;
  onSelectModel: (model: ModelInfo) => void;
  onConfirm?: () => void;
  focused?: boolean;
  isModelUserSelected?: boolean;
}

export function ModelPicker({
  config,
  selectedModel,
  onSelectModel,
  onConfirm,
  focused = true,
  isModelUserSelected = false,
}: ModelPickerProps) {
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );
  const [focusedIndex, setFocusedIndex] = useState(0);

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

  // Handle keyboard navigation
  const handleKeyboard = useCallback(
    (key: {
      name?: string;
      sequence?: string;
      ctrl?: boolean;
      shift?: boolean;
      meta?: boolean;
    }) => {
      if (!focused) return false;
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

      // Enter - confirm model selection or toggle provider header
      if (key.name === "return") {
        const currentItem = navigationItems[focusedIndex];
        if (!currentItem) return false;

        if (currentItem.type === "provider") {
          // Toggle expansion when focused on a provider header
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
          // Confirm selection when focused on a model
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
            : currentItem.model.provider;

        if (key.name === "left") {
          setExpandedProviders((prev) => {
            const next = new Set(prev);
            next.delete(targetProvider);
            return next;
          });
          // Move focus to the provider header when collapsing
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
        // Auto-expand all providers when searching
        if (!searchQuery) {
          setExpandedProviders(new Set(providerOrder));
        }
        return true;
      }

      return false;
    },
    [
      focused,
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
        <text fg={creamText}>Search: {searchQuery}_</text>
      ) : (
        <text fg={dimText}>Type to search models...</text>
      )}

      {/* Provider groups */}
      {providerOrder.map((provider) => {
        const models = groupedModels[provider];
        if (!models || models.length === 0) return null;

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

        return (
          <box key={provider} flexDirection="column" gap={0}>
            {/* Provider header */}
            <text
              fg={
                isProviderFocused
                  ? greenAccent
                  : isExpanded
                    ? creamText
                    : dimText
              }
            >
              {isProviderFocused ? "❯" : isExpanded ? "▾" : "▸"} {providerName}{" "}
              ({models.length})
            </text>

            {/* Models list (when expanded) */}
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
                    <text key={m.id} fg={isFocused ? greenAccent : dimText}>
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
      <text fg={dimText}>
        ↑/↓ navigate | ←/→ collapse/expand | Type to search
      </text>
    </box>
  );
}

export default ModelPicker;
