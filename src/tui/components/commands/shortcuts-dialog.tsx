import { useKeyboard } from "@opentui/react";
import { Dialog } from "../../context/dialog";
import { useFocus } from "../../context/focus";
import { keybindings } from "../../keybindings-registry";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

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
      <DialogLayout title="Keyboard Shortcuts">
        {/* Shortcuts List */}
        <box flexDirection="column" gap={1}>
          {keybindings.map((keybinding) => (
            <box key={keybinding.key} flexDirection="row" gap={2}>
              <text fg={colors.primary} width={15}>
                [{keybinding.key}]
              </text>
              <text fg={colors.text}>{keybinding.description}</text>
            </box>
          ))}
        </box>
      </DialogLayout>
    </Dialog>
  );
}
