import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { AVAILABLE_MODELS, type ModelInfo } from "../../../core/ai";
import { config } from "../../../core/config";
import type { Config } from "../../../core/config/config";
import { useEffect, useState } from "react";

export default function ModelsDisplay({
  closeModels,
}: {
  closeModels: () => void;
}) {
  const [appConfig, setAppConfig] = useState<Config | null>(null);
  const [availableModels, setAvailableModels] =
    useState<ModelInfo[]>(AVAILABLE_MODELS);

  useEffect(() => {
    config.get().then((config) => {
      setAppConfig(config);
      const anthropicEnabled = !!config.anthropicAPIKey;
      const openaiEnabled = !!config.openAiAPIKey;
      const openrouterEnabled = !!config.openRouterAPIKey;
      const bedrockEnabled = !!config.bedrockAPIKey;
      setAvailableModels(
        AVAILABLE_MODELS.filter((model) => {
          if (model.provider === "anthropic") return anthropicEnabled;
          if (model.provider === "openai") return openaiEnabled;
          if (model.provider === "openrouter") return openrouterEnabled;
          if (model.provider === "bedrock") return bedrockEnabled;
          return false;
        })
      );
    });
  }, []);

  useKeyboard((key) => {
    // Escape - Close models display
    if (key.name === "escape") {
      closeModels();
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
          {AVAILABLE_MODELS.map((model) => (
            <box key={model.id} flexDirection="column">
              <text fg="gray">{model.id}</text>
            </box>
          ))}
        </scrollbox>

        <box flexDirection="row" width="100%" gap={1}>
          <text fg="gray">
            <span fg="green">[ESC]</span> Close
          </text>
        </box>
      </box>
    </box>
  );
}
