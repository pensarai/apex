import type { RGBA } from "@opentui/core";
import { useDimensions } from "../context/dimensions";
import { type ToastVariant, useToast } from "../context/toast";
import { useTheme } from "../theme";

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
  onDismiss,
}: {
  message: string;
  variant: ToastVariant;
  onDismiss: () => void;
}) {
  const { colors } = useTheme();
  const accent = variantColor(variant, colors);

  return (
    <box
      flexDirection="row"
      gap={1}
      paddingLeft={1}
      paddingRight={1}
      border={["left"]}
      borderColor={accent}
      backgroundColor={colors.backgroundPanel}
      onMouseUp={() => onDismiss()}
    >
      <text fg={accent}>{VARIANT_ICONS[variant]}</text>
      <text fg={colors.text}>{message}</text>
    </box>
  );
}

export function ToastContainer() {
  const { toasts, dismiss } = useToast();
  const dims = useDimensions();

  if (toasts.length === 0) return null;

  return (
    <box
      position="absolute"
      right={1}
      top={0}
      flexDirection="column"
      gap={0}
      alignItems="flex-end"
      maxWidth={Math.min(80, dims.width - 4)}
      zIndex={9999}
    >
      {toasts.map((t) => (
        <ToastItem
          key={t.id}
          message={t.message}
          variant={t.variant}
          onDismiss={() => dismiss(t.id)}
        />
      ))}
    </box>
  );
}
