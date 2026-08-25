import type { RGBA, ScrollBoxRenderable } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  type AIModelProvider,
  getOpenAIReasoningEfforts,
  getRecentModels,
  type ModelInfo,
  modelSupportsOpenAIReasoning,
  modelSupportsThinking,
  type OpenAIReasoningEffort,
} from "../../../core/ai";
import type { Config } from "../../../core/config/config";
import { getAvailableModels } from "../../../core/providers/utils";
import { useTheme } from "../../theme";
import { getPasteText } from "../../utils/paste";
import { scrollToChild } from "../../utils/scroll";
import {
  findSelectedModelIndex,
  retainAvailableProviders,
} from "./model-navigation";
import { filterModels, getProviderDisplayName } from "./model-search";

const providerOrder: AIModelProvider[] = [
  "pensar",
  "anthropic",
  "openai",
  "google",
  "openrouter",
  "concentrate",
  "bedrock",
  "bedrock-mantle",
  "inception",
  "local",
];

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
  backgroundColor?: string | RGBA;
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
  | { type: "provider"; provider: AIModelProvider }
  | { type: "model"; model: ModelInfo }
  | { type: "recent-model"; model: ModelInfo }
  | { type: "local-input"; field: LocalInputField }
  | { type: "reasoning" }
  | { type: "openai-reasoning" };

type LocalInputField = "url" | "model";

function getNavItemId(item: NavigationItem): string {
  if (item.type === "provider") return `provider-${item.provider}`;
  if (item.type === "model") return `model-${item.model.id}`;
  if (item.type === "recent-model") return `recent-model-${item.model.id}`;
  if (item.type === "reasoning") return "reasoning-toggle";
  if (item.type === "openai-reasoning") return "openai-reasoning-effort";
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
  reasoningEnabled?: boolean;
  onReasoningToggle?: (enabled: boolean) => void;
  openAIReasoningEffort?: OpenAIReasoningEffort;
  onOpenAIReasoningEffortChange?: (effort: OpenAIReasoningEffort) => void;
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
  reasoningEnabled = false,
  onReasoningToggle,
  openAIReasoningEffort = "medium",
  onOpenAIReasoningEffortChange,
}: ModelPickerProps) {
  const { colors } = useTheme();
  const scrollBoxRef = useRef<ScrollBoxRenderable | null>(null);
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<
    Set<AIModelProvider>
  >(new Set([selectedModel.provider]));
  const [focusedIndex, setFocusedIndex] = useState(0);
  const lastRevealedSelectedModelRef = useRef<string | null>(null);
  const lastFocusedSelectedModelIdRef = useRef<string | null>(null);

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
    const availableProviders = new Set<AIModelProvider>(
      availableModels.map((model) => model.provider),
    );

    // Config refreshes may prune expansions, but must not reopen a provider.
    setExpandedProviders((prev) =>
      retainAvailableProviders(prev, availableProviders),
    );
  }, [availableModels]);

  // A genuine model change should reveal its provider exactly once.
  useEffect(() => {
    const selectedModelKey = `${selectedModel.provider}:${selectedModel.id}`;
    if (lastRevealedSelectedModelRef.current === selectedModelKey) return;
    lastRevealedSelectedModelRef.current = selectedModelKey;

    setExpandedProviders((prev) =>
      prev.has(selectedModel.provider)
        ? prev
        : new Set([...prev, selectedModel.provider]),
    );
  }, [selectedModel.id, selectedModel.provider]);

  const filteredModels = useMemo(
    () => filterModels(availableModels, searchQuery),
    [availableModels, searchQuery],
  );
  const isSearching = searchQuery.trim().length > 0;
  const recentModels = useMemo(
    () => getRecentModels(availableModels, config?.recentModelIds ?? []),
    [availableModels, config?.recentModelIds],
  );

  // Group models by provider for the unfiltered browsing view.
  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    for (const m of availableModels) {
      if (!groups[m.provider]) {
        groups[m.provider] = [];
      }
      groups[m.provider].push(m);
    }
    return groups;
  }, [availableModels]);

  // Flat navigation list: provider headers + expanded models
  const navigationItems = useMemo(() => {
    const items: NavigationItem[] = [];
    if (isSearching) {
      for (const model of filteredModels) {
        items.push({ type: "model", model });
      }
    } else {
      for (const model of recentModels) {
        items.push({ type: "recent-model", model });
      }
      for (const provider of providerOrder) {
        if (provider === "local") {
          items.push({ type: "provider", provider: "local" });
          if (expandedProviders.has("local")) {
            items.push({ type: "local-input", field: "url" });
            items.push({ type: "local-input", field: "model" });
            const localModels = groupedModels.local;
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
    }
    if (
      !isSearching &&
      onReasoningToggle &&
      modelSupportsThinking(selectedModel.id)
    ) {
      items.push({ type: "reasoning" });
    }
    if (
      !isSearching &&
      onOpenAIReasoningEffortChange &&
      modelSupportsOpenAIReasoning(selectedModel.id)
    ) {
      items.push({ type: "openai-reasoning" });
    }
    return items;
  }, [
    groupedModels,
    filteredModels,
    recentModels,
    isSearching,
    expandedProviders,
    onReasoningToggle,
    onOpenAIReasoningEffortChange,
    selectedModel.id,
  ]);

  useEffect(() => {
    if (
      isSearching ||
      lastFocusedSelectedModelIdRef.current === selectedModel.id
    ) {
      return;
    }

    const index = findSelectedModelIndex(navigationItems, selectedModel.id);
    if (index === -1) return;

    lastFocusedSelectedModelIdRef.current = selectedModel.id;
    setFocusedIndex(index);
  }, [isSearching, navigationItems, selectedModel.id]);

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

  const thinkingSupported = modelSupportsThinking(selectedModel.id);
  const openAIReasoningSupported = modelSupportsOpenAIReasoning(
    selectedModel.id,
  );
  const openAIReasoningEfforts = getOpenAIReasoningEfforts(selectedModel.id);
  const isReasoningFocused =
    navigationItems[focusedIndex]?.type === "reasoning";
  const isOpenAIReasoningFocused =
    navigationItems[focusedIndex]?.type === "openai-reasoning";
  const cycleOpenAIReasoningEffort = useCallback(() => {
    if (!onOpenAIReasoningEffortChange || openAIReasoningEfforts.length === 0) {
      return;
    }
    const currentIndex = openAIReasoningEfforts.indexOf(openAIReasoningEffort);
    const nextEffort =
      openAIReasoningEfforts[
        (Math.max(currentIndex, 0) + 1) % openAIReasoningEfforts.length
      ]!;
    onOpenAIReasoningEffortChange(nextEffort);
  }, [
    onOpenAIReasoningEffortChange,
    openAIReasoningEffort,
    openAIReasoningEfforts,
  ]);

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

      // Up/Down - navigate through items
      if (key.name === "up" || key.name === "down") {
        if (navigationItems.length === 0) return false;
        const direction = key.name === "up" ? -1 : 1;
        const newIndex =
          (focusedIndex + direction + navigationItems.length) %
          navigationItems.length;
        setFocusedIndex(newIndex);
        return true;
      }

      // Escape - clear search, or cancel/close
      if (key.name === "escape") {
        if (searchQuery) {
          setSearchQuery("");
          setFocusedIndex(0);
          return true;
        }
        if (onCancel) {
          onCancel();
          return true;
        }
        return false;
      }

      const currentItem = navigationItems[focusedIndex];

      if (
        key.name === "space" &&
        currentItem?.type === "reasoning" &&
        onReasoningToggle &&
        thinkingSupported
      ) {
        onReasoningToggle(!reasoningEnabled);
        return true;
      }
      if (
        key.name === "space" &&
        currentItem?.type === "openai-reasoning" &&
        onOpenAIReasoningEffortChange &&
        openAIReasoningSupported
      ) {
        cycleOpenAIReasoningEffort();
        return true;
      }

      // Enter - confirm model selection, toggle provider, or start editing local input
      if (key.name === "return") {
        if (!currentItem) return false;

        if (currentItem.type === "local-input") {
          setEditingLocalField(currentItem.field);
          return true;
        }

        if (currentItem.type === "reasoning") {
          onReasoningToggle?.(!reasoningEnabled);
        } else if (currentItem.type === "openai-reasoning") {
          cycleOpenAIReasoningEffort();
        } else if (currentItem.type === "provider") {
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
        } else if (
          currentItem.type === "model" ||
          currentItem.type === "recent-model"
        ) {
          onSelectModel(currentItem.model);
          onConfirm?.();
        }
        return true;
      }

      // Left/Right - collapse/expand provider
      if (key.name === "left" || key.name === "right") {
        if (isSearching) return false;
        const currentItem = navigationItems[focusedIndex];
        if (
          !currentItem ||
          currentItem.type === "recent-model" ||
          currentItem.type === "reasoning" ||
          currentItem.type === "openai-reasoning"
        ) {
          return false;
        }

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
      reasoningEnabled,
      onReasoningToggle,
      thinkingSupported,
      onOpenAIReasoningEffortChange,
      openAIReasoningSupported,
      cycleOpenAIReasoningEffort,
      isSearching,
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
  const isProviderFocused = (provider: AIModelProvider) =>
    navigationItems[focusedIndex]?.type === "provider" &&
    navigationItems[focusedIndex].provider === provider;

  // Helper to check if a model is focused
  const isModelFocused = (modelId: string, recent = false) => {
    const item = navigationItems[focusedIndex];
    const expectedType = recent ? "recent-model" : "model";
    return item?.type === expectedType && item.model.id === modelId;
  };

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
      flexShrink={1}
      overflow="hidden"
    >
      {/* Search input */}
      <box flexShrink={0} marginBottom={1}>
        <PickerRow>
          <text fg={colors.primary}>Search </text>
          <input
            flexGrow={1}
            value={searchQuery}
            onInput={(value) => {
              setSearchQuery(value);
              setFocusedIndex(0);
            }}
            focused={focused && editingLocalField === null}
            placeholder="family, model name, or provider..."
            textColor={colors.text}
            focusedTextColor={colors.text}
            backgroundColor="transparent"
            cursorColor={colors.textMuted}
          />
        </PickerRow>
        {isSearching && (
          <PickerRow>
            <text fg={colors.primary}>Results ({filteredModels.length})</text>
          </PickerRow>
        )}
      </box>

      {/* Remount when the list shape changes to reset OpenTUI's cached geometry. */}
      <scrollbox
        key={isSearching ? "search-results" : "model-browser"}
        ref={scrollBoxRef}
        style={{
          rootOptions: {
            flexShrink: 1,
            width: "100%",
            overflow: "hidden",
            maxHeight: Math.max(
              1,
              navigationItems.length +
                (!isSearching && recentModels.length > 0 ? 1 : 0),
            ),
          },
          contentOptions: {
            flexDirection: "column",
          },
          scrollbarOptions: {
            trackOptions: {
              foregroundColor: colors.textMuted,
              backgroundColor: colors.backgroundElement,
            },
          },
        }}
        stickyScroll={false}
      >
        {!isSearching && recentModels.length > 0 && (
          <>
            <PickerRow>
              <text fg={colors.primary}>Recent</text>
            </PickerRow>
            {recentModels.map((model) => {
              const isSelected = model.id === selectedModel.id;
              const isFocused = isModelFocused(model.id, true);
              return (
                <PickerRow
                  key={`recent-${model.id}`}
                  id={`recent-model-${model.id}`}
                  backgroundColor={
                    isFocused ? colors.backgroundSelected : undefined
                  }
                >
                  <text>
                    <span fg={isFocused ? colors.primary : colors.text}>
                      {isSelected ? "●" : "○"} {model.name}
                    </span>
                    <span fg={colors.textMuted}>
                      {`  ${getProviderDisplayName(model.provider)}`}
                    </span>
                  </text>
                </PickerRow>
              );
            })}
          </>
        )}
        {isSearching &&
          (filteredModels.length === 0 ? (
            <PickerRow>
              <text fg={colors.textMuted}>No matching models</text>
            </PickerRow>
          ) : (
            filteredModels.map((model) => {
              const isSelected = model.id === selectedModel.id;
              const isFocused = isModelFocused(model.id);
              return (
                <PickerRow
                  key={model.id}
                  id={`model-${model.id}`}
                  backgroundColor={
                    isFocused ? colors.backgroundSelected : undefined
                  }
                >
                  <text>
                    <span fg={isFocused ? colors.primary : colors.text}>
                      {isSelected ? "●" : "○"} {model.name}
                    </span>
                    <span fg={colors.textMuted}>
                      {`  ${getProviderDisplayName(model.provider)}`}
                    </span>
                  </text>
                </PickerRow>
              );
            })
          ))}
        {providerOrder.flatMap((provider) => {
          if (isSearching) return [];
          const isExpanded = expandedProviders.has(provider);
          const providerName = getProviderDisplayName(provider);
          const isFocused = isProviderFocused(provider);

          if (provider === "local") {
            const localModels = groupedModels.local;
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
                        const cleaned = getPasteText(event).replace(
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
                        const cleaned = getPasteText(event).replace(
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

      {/* Reasoning toggle */}
      {!isSearching && onReasoningToggle && thinkingSupported && (
        <box flexShrink={0} paddingTop={1}>
          <PickerRow id="reasoning-toggle">
            <text fg={isReasoningFocused ? colors.primary : colors.text}>
              {reasoningEnabled ? "[x]" : "[ ]"} Extended Thinking
              (Experimental)
            </text>
          </PickerRow>
        </box>
      )}

      {!isSearching &&
        onOpenAIReasoningEffortChange &&
        openAIReasoningSupported && (
          <box flexShrink={0} paddingTop={1}>
            <PickerRow id="openai-reasoning-effort">
              <text
                fg={isOpenAIReasoningFocused ? colors.primary : colors.text}
              >
                Reasoning Effort:{" "}
                {openAIReasoningEffort === "xhigh"
                  ? "extra high"
                  : openAIReasoningEffort}
              </text>
            </PickerRow>
          </box>
        )}

      {/* Help text for inline editing only — general controls are in ModelPickerDialog */}
      {editingLocalField && (
        <box flexShrink={0}>
          <PickerRow>
            <text fg={colors.textMuted}>
              Type or paste | Enter/Esc to confirm
            </text>
          </PickerRow>
        </box>
      )}
    </box>
  );
}
