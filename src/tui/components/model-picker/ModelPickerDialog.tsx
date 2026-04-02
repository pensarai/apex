/**
 * Model Picker Dialog — /models command
 *
 * Wraps ModelPicker in a Dialog overlay, matching the ThemePicker pattern.
 * Used from both home page and operator mode.
 */

import { useAgent } from "../../context/agent";
import { useConfig } from "../../context/config";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import DialogLayout from "../dialog-layout";
import { ModelPicker } from "./ModelPicker";

interface ModelPickerDialogProps {
  onClose: () => void;
}

export default function ModelPickerDialog({ onClose }: ModelPickerDialogProps) {
  const { colors } = useTheme();
  const config = useConfig();
  const {
    model,
    setModel,
    isModelUserSelected,
    reasoningEnabled,
    setReasoningEnabled,
  } = useAgent();

  const title = (
    <text>
      <span fg={colors.primary}>Select AI Model</span>
      <span fg={colors.textMuted}> ({model.name})</span>
      <span fg={colors.textMuted}>
        {" "}
        [{isModelUserSelected ? "user" : "default"}]
      </span>
    </text>
  );

  return (
    <Dialog size="large" onClose={onClose}>
      <DialogLayout
        title={title}
        footerActions={[{ key: "Enter", label: "confirm", variant: "primary" }]}
      >
        <box
          flexDirection="column"
          paddingLeft={1}
          flexShrink={1}
          overflow="hidden"
        >
          <ModelPicker
            config={config.data}
            selectedModel={model}
            onSelectModel={setModel}
            onConfirm={onClose}
            onCancel={onClose}
            onConfigUpdate={config.update}
            focused={true}
            isModelUserSelected={isModelUserSelected}
            reasoningEnabled={reasoningEnabled}
            onReasoningToggle={setReasoningEnabled}
          />
        </box>
      </DialogLayout>
    </Dialog>
  );
}
