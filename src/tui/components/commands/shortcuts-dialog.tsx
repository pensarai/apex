import { useKeyboard } from "@opentui/react";
import { useFocus } from "../../context/focus";
import { Dialog } from "../../context/dialog";
import { keybindings } from "../../keybindings-registry";

interface ShortcutsDialogProps {
  open: boolean;
  onClose: () => void;
}

export default function ShortcutsDialog({ open, onClose }: ShortcutsDialogProps) {
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
      <box
        flexDirection="column"
        padding={2}
        gap={2}
        width="100%"
      >
        {/* Header */}
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg="white">
            Keyboard Shortcuts
          </text>
          <text fg="gray">esc to close</text>
        </box>

        {/* Shortcuts List */}
        <box flexDirection="column" gap={1}>
          {keybindings.map((keybinding, index) => (
            <box key={index} flexDirection="row" gap={2}>
              <text fg="green" width={15}>[{keybinding.key}]</text>
              <text fg="white">{keybinding.description}</text>
            </box>
          ))}
        </box>
      </box>
    </Dialog>
  );
}
