import { useKeyboard, useTerminalDimensions, useRenderer } from "@opentui/react";
import { RGBA } from "@opentui/core";
import type { JSX } from "react";

export interface AlertDialogProps {
  title?: string;
  message?: string;
  open: boolean;
  onClose: () => void;
  children?: React.ReactNode;
  disableEscape?: boolean;
  size?: "medium" | "large";
}

export default function AlertDialog({
  title = "",
  message,
  open,
  onClose,
  children,
  disableEscape = false,
  size = "medium",
}: AlertDialogProps) {
  const dimensions = useTerminalDimensions();
  const renderer = useRenderer();

  useKeyboard((key) => {
    if (!open) return;
    // Escape closes dialog
    if (key.name === "escape" && !disableEscape) {
      onClose();
      key.preventDefault();
    }
  });

  if (!open) return null as unknown as JSX.Element;

  return (
    <box
      onMouseUp={async () => {
        if (renderer.getSelection()) return;
        if (!disableEscape) {
          onClose();
        }
      }}
      width={dimensions.width}
      height={dimensions.height}
      alignItems="center"
      position="absolute"
      paddingTop={dimensions.height / 4}
      left={0}
      top={0}
      zIndex={1000}
      backgroundColor={"transparent"}
    >
      <box
        onMouseUp={async (e: any) => {
          if (renderer.getSelection()) return;
          e.stopPropagation();
        }}
        width={size === "large" ? 80 : 60}
        maxWidth={dimensions.width - 2}
        border={true}
        borderColor="green"
        backgroundColor="black"
        flexDirection="column"
        padding={1}
        paddingTop={1}
      >
        {title ? (
          <box marginBottom={1}>
            <text fg="green">{title}</text>
          </box>
        ) : null}
        <box flexDirection="column">
          {message ? <text fg="white">{message}</text> : children}
        </box>
        {!disableEscape ? (
          <box marginTop={1}>
            <text fg="gray">Press Esc to close</text>
          </box>
        ) : null}
      </box>
    </box>
  );
}
