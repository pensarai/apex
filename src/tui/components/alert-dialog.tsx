import { useKeyboard, useRenderer } from "@opentui/react";
import { useDimensions } from "../context/dimensions";
import type { JSX } from "react";
import { useTheme } from "../theme";

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
  const { colors } = useTheme();
  const dimensions = useDimensions();
  const renderer = useRenderer();

  useKeyboard((key) => {
    if (!open) return;
    key.preventDefault();
    // Escape closes dialog
    if (key.name === "escape" && !disableEscape) {
      onClose();
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
        onMouseUp={async (e: { stopPropagation: () => void }) => {
          if (renderer.getSelection()) return;
          e.stopPropagation();
        }}
        width={size === "large" ? 80 : 60}
        maxWidth={dimensions.width - 2}
        border={true}
        borderColor={colors.primary}
        backgroundColor={colors.backgroundPanel}
        flexDirection="column"
        padding={1}
        paddingTop={1}
      >
        {!disableEscape && (
          <box
            width="100%"
            flexDirection="row"
            justifyContent="flex-end"
            marginBottom={1}
          >
            <text fg={colors.textMuted}>Esc to close</text>
          </box>
        )}
        {title ? (
          <box marginBottom={1}>
            <text fg={colors.primary}>{title}</text>
          </box>
        ) : null}
        <box flexDirection="column">
          {message ? <text fg={colors.text}>{message}</text> : children}
        </box>
      </box>
    </box>
  );
}
