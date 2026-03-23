/**
 * Config View
 *
 * Simplified target configuration for new sessions.
 * Fields: Target URL, Strict scope toggle, Model picker, Start button.
 */

import { useState, useCallback, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { ModelPicker } from "../model-picker/ModelPicker";
import type { ModelInfo } from "../../../core/ai";
import {
  getAvailableModels,
  getDefaultModelForConfig,
} from "../../../core/providers/utils";
import type { Config } from "../../../core/config/config";
import { useTheme } from "../../theme";

type FocusedField = "url" | "scope" | "model" | "start";

interface ConfigViewProps {
  config: Config | null;
  onBack: () => void;
  onStart: (config: SessionConfig) => void;
}

export interface SessionConfig {
  targetUrl: string;
  strictScope: boolean;
  model: ModelInfo;
}

export function ConfigView({ config, onBack, onStart }: ConfigViewProps) {
  const { colors } = useTheme();
  // Form state
  const [targetUrl, setTargetUrl] = useState("https://");
  const [strictScope, setStrictScope] = useState(true);
  const [selectedModel, setSelectedModel] = useState<ModelInfo>(() => {
    if (config) {
      const dynamicDefault = getDefaultModelForConfig(config);
      if (dynamicDefault) return dynamicDefault;
    }
    return {
      id: "claude-sonnet-4-20250514",
      name: "Claude Sonnet 4",
      provider: "anthropic",
    };
  });
  const [isModelUserSelected, setIsModelUserSelected] = useState(false);

  // Focus state
  const [focusedField, setFocusedField] = useState<FocusedField>("url");

  // Re-evaluate default when config changes (e.g. after provider setup)
  useEffect(() => {
    if (config && !isModelUserSelected) {
      const models = getAvailableModels(config);
      if (models.length > 0) {
        const defaultModel = getDefaultModelForConfig(config) ?? models[0];
        setSelectedModel(defaultModel);
      }
    }
  }, [config, isModelUserSelected]);

  // Handle keyboard navigation
  useKeyboard((key) => {
    // ESC - go back
    if (key.name === "escape") {
      onBack();
      return;
    }

    // Tab / Shift+Tab - cycle through fields
    if (key.name === "tab") {
      const fields: FocusedField[] = ["url", "scope", "model", "start"];
      const currentIdx = fields.indexOf(focusedField);
      const nextIdx = key.shift
        ? (currentIdx - 1 + fields.length) % fields.length
        : (currentIdx + 1) % fields.length;
      setFocusedField(fields[nextIdx]);
      return;
    }

    // Arrow keys for field navigation
    if (key.name === "up" || key.name === "down") {
      const fields: FocusedField[] = ["url", "scope", "model", "start"];
      const currentIdx = fields.indexOf(focusedField);

      if (focusedField === "model") {
        // Let model picker handle up/down
        return;
      }

      const nextIdx =
        key.name === "up"
          ? Math.max(0, currentIdx - 1)
          : Math.min(fields.length - 1, currentIdx + 1);
      setFocusedField(fields[nextIdx]);
      return;
    }

    // Space/Enter to toggle scope
    if (
      focusedField === "scope" &&
      (key.name === "space" || key.name === "return")
    ) {
      setStrictScope(!strictScope);
      return;
    }

    // Enter on start button
    if (focusedField === "start" && key.name === "return") {
      if (isValidUrl(targetUrl)) {
        onStart({
          targetUrl,
          strictScope,
          model: selectedModel,
        });
      }
      return;
    }
  });

  const handleModelSelect = useCallback((model: ModelInfo) => {
    setSelectedModel(model);
    setIsModelUserSelected(true);
  }, []);

  const isValid = isValidUrl(targetUrl);

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      paddingLeft={4}
      paddingRight={4}
      gap={1}
      overflow="hidden"
    >
      {/* Header */}
      <box flexDirection="row" justifyContent="space-between">
        <text fg={colors.text}>Configure Session</text>
        <text fg={colors.textMuted}>Esc {"<-"}</text>
      </box>

      {/* Spacer */}
      <box height={1} />

      {/* Target URL Field */}
      <box flexDirection="column" gap={0}>
        <text fg={colors.text}>Target URL</text>
        <box
          border={true}
          borderColor={focusedField === "url" ? colors.primary : colors.border}
          paddingLeft={1}
          paddingRight={1}
        >
          <input
            width="100%"
            value={targetUrl}
            onInput={setTargetUrl}
            focused={focusedField === "url"}
            placeholder="https://example.com"
            textColor={colors.text}
            backgroundColor="transparent"
            cursorColor={colors.textMuted}
          />
        </box>
      </box>

      {/* Spacer */}
      <box height={1} />

      {/* Scope Toggle */}
      <box flexDirection="column" gap={0}>
        <text fg={colors.text}>Scope</text>
        <box
          flexDirection="row"
          gap={1}
          onMouseDown={() => setStrictScope(!strictScope)}
        >
          <text
            fg={focusedField === "scope" ? colors.primary : colors.textMuted}
          >
            {focusedField === "scope" ? ">" : " "}
          </text>
          <text fg={strictScope ? colors.primary : colors.textMuted}>
            [{strictScope ? "●" : " "}]
          </text>
          <text fg={colors.text}>Strict - only target host allowed</text>
        </box>
      </box>

      {/* Spacer */}
      <box height={1} />

      {/* Model Picker */}
      <box flexDirection="column" gap={0}>
        <text fg={colors.text}>Model</text>
        <box
          border={true}
          borderColor={
            focusedField === "model" ? colors.primary : colors.border
          }
          paddingLeft={1}
          paddingRight={1}
          height={8}
          overflow="hidden"
        >
          <ModelPicker
            config={config}
            selectedModel={selectedModel}
            onSelectModel={handleModelSelect}
            focused={focusedField === "model"}
            isModelUserSelected={isModelUserSelected}
          />
        </box>
      </box>

      {/* Spacer */}
      <box height={1} />

      {/* Start Button */}
      <box flexDirection="row" gap={1}>
        <text fg={focusedField === "start" ? colors.primary : colors.textMuted}>
          {focusedField === "start" ? ">" : " "}
        </text>
        <box
          border={true}
          borderColor={
            focusedField === "start" && isValid ? colors.primary : colors.border
          }
          paddingLeft={2}
          paddingRight={2}
          onMouseDown={() => {
            if (isValid) {
              onStart({ targetUrl, strictScope, model: selectedModel });
            }
          }}
        >
          <text fg={isValid ? colors.text : colors.textMuted}>
            [ Start Session ]
          </text>
        </box>
      </box>

      {/* Validation hint */}
      {!isValid && targetUrl.length > 8 && (
        <box marginTop={1}>
          <text fg={colors.error}>Please enter a valid URL (https://...)</text>
        </box>
      )}
    </box>
  );
}

/**
 * Validate URL format
 */
function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

export default ConfigView;
