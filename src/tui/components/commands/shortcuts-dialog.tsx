import { useKeyboard } from "@opentui/react";
import { useFocus } from "../../context/focus";
import { useKeybinding } from "../../context/keybinding";
import { Dialog } from "../../context/dialog";
import { formatKeybindingCombo } from "../../keybindings";
import { useTheme } from "../../theme";

interface ShortcutsDialogProps {
  open: boolean;
  onClose: () => void;
}

export default function ShortcutsDialog({
  open,
  onClose,
}: ShortcutsDialogProps) {
  const { colors } = useTheme();
  const { refocusPrompt } = useFocus();
  const { registry } = useKeybinding();

  useKeyboard((key) => {
    if (key.name === "escape") {
      refocusPrompt();
      onClose();
      return;
    }
  });

  if (!open) return null;

  const handleClose = () => {
    refocusPrompt();
    onClose();
  };

  return (
    <Dialog size="large" onClose={handleClose}>
      <box flexDirection="column" padding={2} gap={2} width="100%">
        {/* Header */}
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg={colors.text}>Keyboard Shortcuts</text>
          <text fg={colors.textMuted}>esc to close</text>
        </box>

        {/* Shortcuts List */}
        <box flexDirection="column" gap={1}>
          {registry.map((keybinding) => (
            <box key={keybinding.id} flexDirection="row" gap={2}>
              <text fg={colors.primary} width={15}>
                [{formatKeybindingCombo(keybinding.combo)}]
              </text>
              <text fg={colors.text}>{keybinding.description}</text>
            </box>
          ))}
        </box>
      </box>
    </Dialog>
  );
}
