import { useKeyboard } from "@opentui/react";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { ModelPicker } from "../model-picker";
import { useTheme } from "../../theme";

export default function ModelsDisplay() {
  const { colors } = useTheme();
  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  const goHome = () => {
    route.navigate({
      type: "base",
      path: "home",
    });
  };

  useKeyboard((key) => {
    // Escape - Go back
    if (key.name === "escape") {
      goHome();
      return;
    }

    // Ctrl+P - Connect provider
    if (key.ctrl && key.name === "p") {
      route.navigate({
        type: "base",
        path: "providers",
      });
      return;
    }
  });

  return (
    <box flexDirection="column" width="100%" paddingLeft={4} paddingTop={2}>
      {/* Header */}
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={colors.text}>Select AI Model</span>
        <span fg={colors.textMuted}> ({model.name})</span>
        <span fg={colors.textMuted}>
          {" "}
          [{isModelUserSelected ? "user" : "default"}]
        </span>
      </text>

      {/* Model Picker */}
      <box flexDirection="column" paddingLeft={2} marginTop={1}>
        <ModelPicker
          config={config.data}
          selectedModel={model}
          onSelectModel={setModel}
          onConfirm={goHome}
          focused={true}
          isModelUserSelected={isModelUserSelected}
        />
      </box>

      {/* Footer */}
      <box flexDirection="column" marginTop={2}>
        <text>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.textMuted}>Press </span>
          <span fg={colors.text}>[Enter]</span>
          <span fg={colors.textMuted}> to confirm</span>
        </text>
        <text>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.textMuted}>Press </span>
          <span fg={colors.text}>[ESC]</span>
          <span fg={colors.textMuted}> to go back</span>
        </text>
        <text>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.textMuted}>Press </span>
          <span fg={colors.text}>[Ctrl+P]</span>
          <span fg={colors.textMuted}> to connect provider</span>
        </text>
      </box>
    </box>
  );
}
