import {
  useState,
  useEffect,
  useMemo,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import type { ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import type { Config } from "../../../core/config/config";
import { useTheme } from "../../theme";
import { scrollToChild } from "../../utils/scroll";

const providerNames: Record<string, string> = {
  anthropic: "Claude",
  openai: "OpenAI",
  google: "Gemini",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
  pensar: "Pensar",
  local: "Local LLM",
};

const providerOrder = [
  "pensar",
  "anthropic",
  "openai",
  "google",
  "openrouter",
  "bedrock",
  "local",
];

function setsAreEqual(a: Set<string>, b: Set<string>) {
  return a.size === b.size && [...a].every((value) => b.has(value));
}

function PickerRow({
  children,
  id,
  paddingLeft,
  paddingRight,
  backgroundColor,
  flexDirection = "row",
  gap = 0,
}: {
  children: ReactNode;
  id?: string;
  paddingLeft?: number;
  paddingRight?: number;
  backgroundColor?: string;
  flexDirection?: "row" | "column";
  gap?: number;
}) {
  return (
    <box
      id={id}
      width="100%"
      overflow="hidden"
      flexDirection={flexDirection}
      paddingLeft={paddingLeft}
      paddingRight={paddingRight}
      backgroundColor={backgroundColor}
      gap={gap}
    >
      {children}
    </box>
  );
}

type NavigationItem =
  | { type: "provider"; provider: string }
  | { type: "model"; model: ModelInfo }
  | { type: "local-input"; field: LocalInputField };

type LocalInputField = "url" | "model";

function getNavItemId(item: NavigationItem): string {
  if (item.type === "provider") return `provider-${item.provider}`;
  if (item.type === "model") return `model-${item.model.id}`;
  return `local-input-${item.field}`;
}

export interface ModelPickerProps {
  config: Config | null;
  selectedModel: ModelInfo;
  onSelectModel: (model: ModelInfo) => void;
  onConfirm?: () => void;
  onCancel?: () => void;
  onConfigUpdate?: (update: Partial<Config>) => Promise<void>;
  focused?: boolean;
  isModelUserSelected?: boolean;
}

export function ModelPicker({
  config,
  selectedModel,
  onSelectModel,
  onConfirm,
  onCancel,
  onConfigUpdate,
  focused = true,
  isModelUserSelected = false,
}: ModelPickerProps) {
  const { colors } = useTheme();
  const scrollBoxRef = useRef<ScrollBoxRenderable | null>(null);
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
    if (!config) {
      setAvailableModels([]);
      return;
    }

    setAvailableModels(getAvailableModels(config));
  }, [config]);

  useEffect(() => {
    const availableProviders = new Set<string>(
      availableModels.map((model) => model.provider),
    );

    setExpandedProviders((prev) => {
      if (availableProviders.size === 0) {
        return prev.size === 0 ? prev : new Set();
      }

      const preservedProviders = new Set(
        [...prev].filter((provider) => availableProviders.has(provider)),
      );

      if (preservedProviders.size > 0) {
        return setsAreEqual(prev, preservedProviders)
          ? prev
          : preservedProviders;
      }

      const fallbackProvider = availableProviders.has(selectedModel.provider)
        ? selectedModel.provider
        : availableModels[0]?.provider;

      if (!fallbackProvider) {
        return prev.size === 0 ? prev : new Set();
      }

      return prev.size === 1 && prev.has(fallbackProvider)
        ? prev
        : new Set([fallbackProvider]);
    });
  }, [availableModels, selectedModel.provider]);

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

  // Scroll to keep focused item visible
  useEffect(() => {
    const item = navigationItems[focusedIndex];
    if (!item) return;
    scrollToChild(scrollBoxRef.current, getNavItemId(item));
  }, [focusedIndex, navigationItems]);

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

      // Escape - clear search, or cancel/close
      if (key.name === "escape") {
        if (searchQuery) {
          setSearchQuery("");
          return true;
        }
        if (onCancel) {
          onCancel();
          return true;
        }
        return false;
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
      onCancel,
      searchQuery,
    ],
  );

  useKeyboard((key) => {
    const handled = handleKeyboard(key);
    if (handled) {
      // Only consume keystrokes that the picker actually handled,
      // so unhandled keys (e.g. ESC without onCancel, Tab) fall through
      // to parent components like ConfigView.
      key.preventDefault();
    }
  });

  // Helper to check if a navigation item at focusedIndex matches a provider
  const isProviderFocused = (provider: string) =>
    navigationItems[focusedIndex]?.type === "provider" &&
    (navigationItems[focusedIndex] as { type: "provider"; provider: string })
      .provider === provider;

  // Helper to check if a model is focused
  const isModelFocused = (modelId: string) =>
    navigationItems[focusedIndex]?.type === "model" &&
    (navigationItems[focusedIndex] as { type: "model"; model: ModelInfo }).model
      .id === modelId;

  // Helper to check if a local input field is focused
  const isLocalFieldFocused = (field: LocalInputField) =>
    navigationItems[focusedIndex]?.type === "local-input" &&
    (
      navigationItems[focusedIndex] as {
        type: "local-input";
        field: LocalInputField;
      }
    ).field === field;

  return (
    <box
      flexDirection="column"
      gap={0}
      width="100%"
      flexGrow={1}
      flexShrink={1}
      overflow="hidden"
    >
      {/* Search indicator */}
      <box flexShrink={0}>
        {searchQuery ? (
          <PickerRow>
            <text fg={colors.text}>Search: {searchQuery}</text>
          </PickerRow>
        ) : (
          <PickerRow>
            <text fg={colors.textMuted}>Type to search models...</text>
          </PickerRow>
        )}
      </box>

      {/* Scrollable provider/model list */}
      <scrollbox
        ref={scrollBoxRef}
        style={{
          rootOptions: {
            flexGrow: 1,
            flexShrink: 1,
            width: "100%",
            overflow: "hidden",
          },
          contentOptions: {
            flexDirection: "column",
          },
          scrollbarOptions: {
            visible: false,
          },
        }}
        stickyScroll={false}
      >
        {providerOrder.flatMap((provider) => {
          const isExpanded = expandedProviders.has(provider);
          const providerName = providerNames[provider] || provider;
          const isFocused = isProviderFocused(provider);

          if (provider === "local") {
            const localModels = groupedModels["local"];
            const modelCount = localModels?.length ?? 0;
            const elements: ReactNode[] = [];

            // Local provider header
            elements.push(
              <PickerRow key="local" id="provider-local">
                <text
                  fg={
                    isFocused
                      ? colors.primary
                      : isExpanded
                        ? colors.text
                        : colors.textMuted
                  }
                >
                  {isFocused ? "❯" : isExpanded ? "▾" : "▸"} {providerName}
                  {modelCount > 0 ? ` (${modelCount})` : ""}
                </text>
              </PickerRow>,
            );

            if (isExpanded) {
              // URL input
              const isUrlFocused = isLocalFieldFocused("url");
              const isUrlEditing = editingLocalField === "url";
              if (isUrlEditing) {
                elements.push(
                  <PickerRow
                    key="local-url"
                    id="local-input-url"
                    paddingLeft={2}
                  >
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
                  </PickerRow>,
                );
              } else {
                elements.push(
                  <PickerRow
                    key="local-url"
                    id="local-input-url"
                    paddingLeft={2}
                  >
                    <text fg={isUrlFocused ? colors.primary : colors.textMuted}>
                      {`  URL: ${localUrl || "(press Enter to set)"}`}
                    </text>
                  </PickerRow>,
                );
              }

              // Model name input
              const isModelFieldFocused = isLocalFieldFocused("model");
              const isModelEditing = editingLocalField === "model";
              if (isModelEditing) {
                elements.push(
                  <PickerRow
                    key="local-model"
                    id="local-input-model"
                    paddingLeft={2}
                  >
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
                  </PickerRow>,
                );
              } else {
                elements.push(
                  <PickerRow
                    key="local-model"
                    id="local-input-model"
                    paddingLeft={2}
                  >
                    <text
                      fg={
                        isModelFieldFocused ? colors.primary : colors.textMuted
                      }
                    >
                      {`  Model: ${localModelName || "(press Enter to set)"}`}
                    </text>
                  </PickerRow>,
                );
              }

              // Local models
              if (localModels) {
                for (const m of localModels) {
                  const isSelected = m.id === selectedModel.id;
                  const isMFocused = isModelFocused(m.id);
                  elements.push(
                    <PickerRow key={m.id} id={`model-${m.id}`} paddingLeft={2}>
                      <text fg={isMFocused ? colors.primary : colors.textMuted}>
                        {isSelected ? "●" : "○"} {m.name}
                      </text>
                    </PickerRow>,
                  );
                }
              }
            }

            return elements;
          }

          const models = groupedModels[provider];
          if (!models || models.length === 0) return [];

          const elements: ReactNode[] = [];

          // Provider header
          elements.push(
            <PickerRow key={provider} id={`provider-${provider}`}>
              <text
                fg={
                  isFocused
                    ? colors.primary
                    : isExpanded
                      ? colors.text
                      : colors.textMuted
                }
              >
                {isFocused ? "❯" : isExpanded ? "▾" : "▸"} {providerName} (
                {models.length})
              </text>
            </PickerRow>,
          );

          // Model rows
          if (isExpanded) {
            for (const m of models) {
              const isSelected = m.id === selectedModel.id;
              const isMFocused = isModelFocused(m.id);
              const isDefault =
                m.id === "claude-haiku-4-5" || m.id === "gpt-4o-mini";
              elements.push(
                <PickerRow key={m.id} id={`model-${m.id}`} paddingLeft={2}>
                  <text fg={isMFocused ? colors.primary : colors.textMuted}>
                    {isSelected ? "●" : "○"} {m.name}
                    {isDefault && !isModelUserSelected && isSelected
                      ? " [default]"
                      : ""}
                  </text>
                </PickerRow>,
              );
            }
          }

          return elements;
        })}
      </scrollbox>

      {/* Help text */}
      <box flexShrink={0}>
        <PickerRow>
          <text fg={colors.textMuted}>
            {editingLocalField
              ? "Type or paste | Enter/Esc to confirm"
              : "↑/↓ navigate | ←/→ collapse/expand | Type to search"}
          </text>
        </PickerRow>
      </box>
    </box>
  );
}

export default ModelPicker;
