import { RGBA } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import type { JSX } from "react";

export interface AlertDialogProps {
  title?: string;
  message: string;
  open: boolean;
  onClose: () => void;
}

export default function AlertDialog({
  title = "",
  message,
  open,
  onClose,
}: AlertDialogProps) {
  useKeyboard((key) => {
    if (!open) return;
    // Escape closes dialog
    if (key.name === "escape") {
      onClose();
    }
  });

  if (!open) return null as unknown as JSX.Element;
  return (
    <box
      position="absolute"
      top={0}
      backgroundColor={RGBA.fromInts(0, 0, 0, 150)}
      left={0}
      zIndex={1000}
      width="100%"
      height="100%"
      justifyContent="center"
      alignItems="center"
    >
      <box
        width={50}
        border={true}
        borderColor="green"
        backgroundColor="black"
        flexDirection="column"
        padding={1}
      >
        {title ? (
          <box marginBottom={1}>
            <text fg="green">{title}</text>
          </box>
        ) : null}
        <box>
          <text fg="white">{message}</text>
        </box>
        <box marginTop={1}>
          <text fg="gray">Press Esc to close</text>
        </box>
      </box>
    </box>
  );
}
