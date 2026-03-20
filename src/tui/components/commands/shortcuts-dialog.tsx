import { useKeyboard } from "@opentui/react";
import { useFocus } from "../../context/focus";
import { Dialog } from "../../context/dialog";
import { keybindings } from "../../keybindings-registry";
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
        <box width="100%">
          <text fg={colors.text}>Keyboard Shortcuts</text>
        </box>

        {/* Shortcuts List */}
        <box flexDirection="column" gap={1}>
          {keybindings.map((keybinding, index) => (
            <box key={index} flexDirection="row" gap={2}>
              <text fg={colors.primary} width={15}>
                [{keybinding.key}]
              </text>
              <text fg={colors.text}>{keybinding.description}</text>
            </box>
          ))}
        </box>
      </box>
    </Dialog>
  );
}
