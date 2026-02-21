import { useTerminalDimensions } from "@opentui/react";
import { useEffect, useState } from "react";
import type { RGBA } from "@opentui/core";
import { useTheme } from "../theme";
import { type ToastVariant, useToast } from "../context/toast";

const VARIANT_ICONS: Record<ToastVariant, string> = {
  default: "●",
  error: "✖",
  warn: "⚠",
};

function variantColor(
  variant: ToastVariant,
  colors: { error: RGBA; warning: RGBA; info: RGBA },
): RGBA {
  switch (variant) {
    case "error":
      return colors.error;
    case "warn":
      return colors.warning;
    default:
      return colors.info;
  }
}

function ToastItem({
  message,
  variant,
  duration,
  onDismiss,
}: {
  message: string;
  variant: ToastVariant;
  duration: number;
  onDismiss: () => void;
}) {
  const { colors } = useTheme();
  const [visible, setVisible] = useState(true);
  const accent = variantColor(variant, colors);

  useEffect(() => {
    const fadeTimer = setTimeout(() => setVisible(false), duration - 300);
    return () => clearTimeout(fadeTimer);
  }, [duration]);

  if (!visible) return null;

  return (
    <box
      flexDirection="row"
      gap={1}
      paddingLeft={1}
      paddingRight={1}
      border={["left"]}
      borderColor={accent}
      backgroundColor={colors.backgroundPanel}
      onMouseUp={async () => onDismiss()}
    >
      <text fg={accent}>{VARIANT_ICONS[variant]}</text>
      <text fg={colors.text}>{message}</text>
    </box>
  );
}

export function ToastContainer() {
  const { toasts, dismiss } = useToast();
  const dims = useTerminalDimensions();

  if (toasts.length === 0) return null;

  return (
    <box
      position="absolute"
      right={1}
      top={0}
      flexDirection="column"
      gap={0}
      alignItems="flex-end"
      maxWidth={Math.min(60, dims.width - 4)}
      zIndex={9999}
    >
      {toasts.map((t) => (
        <ToastItem
          key={t.id}
          message={t.message}
          variant={t.variant}
          duration={t.duration}
          onDismiss={() => dismiss(t.id)}
        />
      ))}
    </box>
  );
}
