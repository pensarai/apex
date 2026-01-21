import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { ModelPicker } from "../model-picker";

const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

export default function ModelsDisplay() {
  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  useKeyboard((key) => {
    // Escape - Close models display
    if (key.name === "escape") {
      route.navigate({
        type: "base",
        path: "home",
      });
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

    // Enter - Confirm selection and close
    if (key.name === "return") {
      route.navigate({
        type: "base",
        path: "home",
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
