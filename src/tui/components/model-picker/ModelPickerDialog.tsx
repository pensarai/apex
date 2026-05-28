/**
 * Model Picker Dialog — /models command
 *
 * Wraps ModelPicker in a Dialog overlay, matching the ThemePicker pattern.
 * Used from both home page and operator mode.
 */

import {
  modelSupportsOpenAIReasoning,
  modelSupportsThinking,
} from "../../../core/ai";
import { useAgent } from "../../context/agent";
import { useConfig } from "../../context/config";
import { Dialog } from "../../context/dialog";
import { useTheme } from "../../theme";
import type { FooterAction } from "../dialog-layout";
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
    openAIReasoningEffort,
    setOpenAIReasoningEffort,
  } = useAgent();

  const thinkingSupported = modelSupportsThinking(model.id);
  const openAIReasoningSupported = modelSupportsOpenAIReasoning(model.id);

  const footerActions: FooterAction[] = [
    { key: "Enter", label: "confirm", variant: "primary" },
  ];
  if (thinkingSupported) {
    footerActions.push({ key: "Space", label: "Extended Thinking" });
  }
  if (openAIReasoningSupported) {
    footerActions.push({ key: "Space", label: "Reasoning Effort" });
  }

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
      <DialogLayout title={title} footerActions={footerActions}>
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
            openAIReasoningEffort={openAIReasoningEffort}
            onOpenAIReasoningEffortChange={setOpenAIReasoningEffort}
          />
        </box>
      </DialogLayout>
    </Dialog>
  );
}
