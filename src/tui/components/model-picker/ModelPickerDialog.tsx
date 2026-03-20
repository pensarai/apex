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
import { DialogControls } from "../shared/dialog-controls";
import { ModelPicker } from "./ModelPicker";

interface ModelPickerDialogProps {
  onClose: () => void;
}

export default function ModelPickerDialog({ onClose }: ModelPickerDialogProps) {
  const { colors } = useTheme();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  return (
    <Dialog size="large" onClose={onClose}>
      <box flexDirection="column" width="100%" paddingLeft={2} paddingTop={1}>
        <box flexShrink={0} width="100%" overflow="hidden">
          <text>
            <span fg={colors.primary}>Select AI Model</span>
            <span fg={colors.textMuted}> ({model.name})</span>
            <span fg={colors.textMuted}>
              {" "}
              [{isModelUserSelected ? "user" : "default"}]
            </span>
          </text>
        </box>
        <box
          flexDirection="column"
          paddingLeft={1}
          marginTop={1}
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
          />
        </box>
        <box marginTop={1} paddingLeft={1} flexShrink={0}>
          <DialogControls
            controls={[
              { key: "Enter", label: "Confirm", variant: "primary" },
              { key: "↑/↓", label: "Navigate" },
              { key: "←/→", label: "Collapse/Expand" },
            ]}
          />
        </box>
      </box>
    </Dialog>
  );
}
