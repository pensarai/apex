import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { type ModelInfo } from "../../../core/ai";
import { useAgent } from "../../context/agent";
import { useEffect, useState } from "react";
import type { Config } from "../../../core/config/config";
import { config } from "../../../core/config";
import Input from "../input";
import { AVAILABLE_MODELS } from "../../../core/ai/models";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";

export default function ModelsDisplay() {
  const route = useRoute();
  const _config = useConfig();
  
  const [models, setModels] = useState<ModelInfo[]>([]);
  const { model: selectedModel, setModel } = useAgent();
  const [customModel, setCustomModel] = useState<string>("");
  const [focusArea, setFocusArea] = useState<"custom" | "list">("custom");

  const [highlightedIndex, setHighlightedIndex] = useState(() =>
    models.findIndex((m) => m.id === selectedModel.id)
  );


  useEffect(() => {
    async function getConfig() {
      const openAiConfigured = !!_config.data.openAiAPIKey;
      const anthropicConfigured = !!_config.data.anthropicAPIKey;
      const bedrockConfigured = !!_config.data.bedrockAPIKey;
      const openRouterConfigured = !!_config.data.openRouterAPIKey;
      const _models = AVAILABLE_MODELS.filter((m) => {
        if (m.provider === "openai") return openAiConfigured;
        if (m.provider === "anthropic") return anthropicConfigured;
        if (m.provider === "bedrock") return bedrockConfigured;
        if (m.provider === "openrouter") return openRouterConfigured;
        return false;
      });

      setModels(_models);
    }
    getConfig();
  }, []);

  useKeyboard((key) => {
    // Escape - Close models display
    if (key.name === "escape") {
      route.navigate({
        type: "base",
        path: "home"
      });
      return;
    }

    // Tab focus switching between custom input and list
    if (key.name === "tab" && !key.shift) {
      setFocusArea((prev) => (prev === "custom" ? "list" : "custom"));
      return;
    }
    if (key.name === "tab" && key.shift) {
      setFocusArea((prev) => (prev === "list" ? "custom" : "list"));
      return;
    }

    // When list is focused, handle navigation and selection
    if (focusArea === "list") {
      // Arrow Up - Previous model
      if (key.name === "up" && models.length > 0) {
        setHighlightedIndex((prev) =>
          prev > 0 ? prev - 1 : models.length - 1
        );
        return;
      }

      // Arrow Down - Next model
      if (key.name === "down" && models.length > 0) {
        setHighlightedIndex((prev) =>
          prev < models.length - 1 ? prev + 1 : 0
        );
        return;
      }

      // Enter - Select model
      if (key.name === "return" && models.length > 0) {
        const sel = models[highlightedIndex];
        if (sel) {
          setModel(sel);
          route.navigate({
            type: "base",
            path: "home"
          });
        }
        return;
      }
    }
  });

  return (
    <box
      alignItems="center"
      justifyContent="center"
      flexDirection="column"
      backgroundColor={RGBA.fromInts(0, 0, 0, 100)}
      width="100%"
      maxHeight="100%"
      flexGrow={1}
      flexShrink={1}
      overflow="hidden"
      gap={1}
    >
      <box flexDirection="column" width="80%" gap={1}>
        <text fg="green">Available Models</text>
        <text fg="white">
          Current: <span fg="green">{selectedModel.name}</span>
        </text>

        <box flexDirection="column" gap={1}>
          <Input
            label="Custom local model (vLLM)"
            description="Requires LOCAL_MODEL_URL env var. Press Enter to set."
            value={customModel}
            focused={focusArea === "custom"}
            onChange={(value) =>
              setCustomModel(typeof value === "string" ? value : "")
            }
            onPaste={(event) => {
              const cleaned = String(event.text);
              setCustomModel((prev) => `${prev}${cleaned}`);
            }}
            onSubmit={() => {
              const id = customModel.trim();
              if (!id) return;
              const localModel: ModelInfo = { id, name: id, provider: "local" };
              setModel(localModel);
              setCustomModel("");
              route.navigate({
                type: "base",
                path: "home"
              });
            }}
          />
        </box>

        <scrollbox
          style={{
            rootOptions: {
              width: "100%",
              maxWidth: "100%",
              flexGrow: 1,
              flexShrink: 1,
              overflow: "hidden",
              borderColor: "green",
              focusedBorderColor: "green",
              border: true,
              paddingLeft: 1,
              paddingRight: 1,
            },
            wrapperOptions: {
              overflow: "hidden",
            },
            contentOptions: {
              flexGrow: 1,
              flexDirection: "column",
              gap: 1,
            },
            scrollbarOptions: {
              trackOptions: {
                foregroundColor: "green",
                backgroundColor: RGBA.fromInts(40, 40, 40, 255),
              },
            },
          }}
          focused={focusArea === "list"}
        >
          {models.map((model, index) => {
            const isSelected = model.id === selectedModel.id;
            const isHighlighted = index === highlightedIndex;

            return (
              <box
                key={model.id}
                flexDirection="column"
                gap={0}
                onMouseDown={() => {
                  setModel(model);
                  route.navigate({
                    type: "base",
                    path: "home"
                  });
                }}
              >
                <text
                  fg={isHighlighted ? "green" : isSelected ? "white" : "gray"}
                >
                  {isHighlighted ? "▶ " : "  "}
                  {model.name}
                  {isSelected ? " ✓" : ""}
                </text>
                <text fg="gray"> {model.id}</text>
                <text fg="gray"> {model.provider}</text>
              </box>
            );
          })}
        </scrollbox>

        <box flexDirection="row" width="100%" gap={1}>
          <text fg="gray">
            <span fg="green">[TAB]</span> Focus input/list ·{" "}
            <span fg="green">[↑↓]</span> Navigate list ·{" "}
            <span fg="green">[ENTER]</span> Select ·{" "}
            <span fg="green">[ESC]</span> Close
          </text>
        </box>
      </box>
    </box>
  );
}
