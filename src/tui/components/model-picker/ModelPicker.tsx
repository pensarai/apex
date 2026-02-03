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

export interface ModelPickerProps {
  config: Config | null;
  selectedModel: ModelInfo;
  onSelectModel: (model: ModelInfo) => void;
  focused?: boolean;
  isModelUserSelected?: boolean;
}

export function ModelPicker({
  config,
  selectedModel,
  onSelectModel,
  focused = true,
  isModelUserSelected = false,
}: ModelPickerProps) {
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"])
  );

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

  // Flat list of visible models for keyboard navigation
  const visibleModels = useMemo(() => {
    const result: ModelInfo[] = [];
    for (const provider of providerOrder) {
      const models = groupedModels[provider];
      if (!models || models.length === 0) continue;
      if (expandedProviders.has(provider)) {
        result.push(...models);
      }
    }
    return result;
  }, [groupedModels, expandedProviders]);

  // Handle keyboard navigation
  const handleKeyboard = useCallback(
    (key: any) => {
      if (!focused) return false;

      // Up/Down - navigate through visible models
      if (key.name === "up" || key.name === "down") {
        if (visibleModels.length > 0) {
          const currentVisibleIndex = visibleModels.findIndex(
            (m) => m.id === selectedModel.id
          );
          const newVisibleIndex =
            key.name === "up"
              ? Math.max(0, currentVisibleIndex - 1)
              : Math.min(visibleModels.length - 1, currentVisibleIndex + 1);
          const newModel = visibleModels[newVisibleIndex];
          if (newModel) {
            onSelectModel(newModel);
          }
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

      // Left/Right - toggle provider expansion
      if (key.name === "left" || key.name === "right") {
        const currentProvider = selectedModel.provider;
        if (key.name === "left") {
          setExpandedProviders((prev) => {
            const next = new Set(prev);
            next.delete(currentProvider);
            return next;
          });
        } else {
          setExpandedProviders((prev) => new Set([...prev, currentProvider]));
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
    [focused, visibleModels, selectedModel, onSelectModel, searchQuery]
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

        return (
          <box key={provider} flexDirection="column" gap={0}>
            {/* Provider header */}
            <text fg={isExpanded ? creamText : dimText}>
              {isExpanded ? "▾" : "▸"} {providerName} ({models.length})
            </text>

            {/* Models list (when expanded) */}
            {isExpanded && (
              <box flexDirection="column" gap={0} paddingLeft={2}>
                {models.map((m) => {
                  const isSelected = m.id === selectedModel.id;
                  const isDefault =
                    m.id === "claude-haiku-4-5" || m.id === "gpt-4o-mini";
                  return (
                    <text key={m.id} fg={isSelected ? greenAccent : dimText}>
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
      <text fg={dimText}>↑/↓ select | Type to search | ←/→ collapse/expand</text>
    </box>
  );
}

export default ModelPicker;
