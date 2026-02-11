import { useKeyboard } from "@opentui/react";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { ModelPicker } from "../model-picker";
import { useColors } from "../../theme";

export default function ModelsDisplay() {
  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();
  const colors = useColors();
  const { greenAccent, creamText, dimText } = colors;

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
        <span fg={greenAccent}>█ </span>
        <span fg={creamText}>Select AI Model</span>
        <span fg={dimText}> ({model.name})</span>
        <span fg={dimText}> [{isModelUserSelected ? "user" : "default"}]</span>
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
          <span fg={greenAccent}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Enter]</span>
          <span fg={dimText}> to confirm</span>
        </text>
        <text>
          <span fg={greenAccent}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[ESC]</span>
          <span fg={dimText}> to go back</span>
        </text>
        <text>
          <span fg={greenAccent}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Ctrl+P]</span>
          <span fg={dimText}> to connect provider</span>
        </text>
      </box>
    </box>
  );
}
