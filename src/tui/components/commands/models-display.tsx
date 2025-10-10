import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { AVAILABLE_MODELS, type ModelInfo } from "../../../core/ai";
import { useAgent } from "../../agentProvider";
import { useEffect, useState } from "react";
import type { Config } from "../../../core/config/config";
import { config } from "../../../core/config";

export default function ModelsDisplay({
  closeModels,
}: {
  closeModels: () => void;
}) {
  const [appConfig, setAppConfig] = useState<Config | null>(null);
  const [models, setModels] = useState<ModelInfo[]>([]);
  const { model: selectedModel, setModel } = useAgent();

  const [highlightedIndex, setHighlightedIndex] = useState(() =>
    models.findIndex((m) => m.id === selectedModel.id)
  );

  useEffect(() => {
    async function getConfig() {
      const _config = await config.get();
      setAppConfig(_config);
      const openAiConfigured = !!_config.openAiAPIKey;
      const anthropicConfigured = !!_config.anthropicAPIKey;
      const bedrockConfigured = !!_config.bedrockAPIKey;
      const openRouterConfigured = !!_config.openRouterAPIKey;
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
      closeModels();
      return;
    }

    // Arrow Up - Previous model
    if (key.name === "up" && models.length > 0) {
      setHighlightedIndex((prev) => (prev > 0 ? prev - 1 : models.length - 1));
      return;
    }

    // Arrow Down - Next model
    if (key.name === "down" && models.length > 0) {
      setHighlightedIndex((prev) => (prev < models.length - 1 ? prev + 1 : 0));
      return;
    }

    // Enter - Select model
    if (key.name === "return" && models.length > 0) {
      const selectedModel = models[highlightedIndex];
      if (selectedModel) {
        setModel(selectedModel);
        closeModels();
      }
      return;
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
          focused
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
                  closeModels();
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
            <span fg="green">[↑↓]</span> Navigate ·{" "}
            <span fg="green">[ENTER]</span> Select ·{" "}
            <span fg="green">[ESC]</span> Close
          </text>
        </box>
      </box>
    </box>
  );
}
