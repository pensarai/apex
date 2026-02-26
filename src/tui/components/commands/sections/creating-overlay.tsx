import type { RGBA } from "@opentui/core";
import { SpinnerDots } from "../../sprites";
import { useTheme } from "../../../theme";

interface CreatingOverlayProps {
  target: string;
  /** Optional mode label to display (e.g., "Auto Mode", operator mode name) */
  modeLabel?: string;
  /** Color for mode label. Defaults to theme primary */
  modeLabelColor?: RGBA;
  /** Label shown next to spinner. Defaults to "Creating session..." */
  spinnerLabel?: string;
}

export function CreatingOverlay({
  target,
  modeLabel,
  modeLabelColor,
  spinnerLabel = "Creating session...",
}: CreatingOverlayProps) {
  const { colors } = useTheme();
  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
      justifyContent="center"
      flexGrow={1}
      gap={2}
    >
      <SpinnerDots label={spinnerLabel} fg={colors.primary} />
      <text fg={colors.textMuted}>Target: {target}</text>
      {modeLabel && (
        <text fg={modeLabelColor ?? colors.primary}>Mode: {modeLabel}</text>
      )}
    </box>
  );
}
