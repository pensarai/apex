/**
 * Verified Vulns Panel - Shows confirmed findings with POCs
 */

import type { RGBA } from "@opentui/core";
import type { VerifiedVuln } from "../types";
import { useTheme, type ThemeColors } from "../../../theme";

interface VerifiedVulnsPanelProps {
  vulns: VerifiedVuln[];
  maxVisible?: number;
}

export function VerifiedVulnsPanel({
  vulns,
  maxVisible = 5,
}: VerifiedVulnsPanelProps) {
  const { colors } = useTheme();
  const visible = vulns.slice(0, maxVisible);
  const remaining = vulns.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.text}>
        Verified Vulns{" "}
        {vulns.length > 0 && <span fg={colors.primary}>({vulns.length})</span>}
      </text>

      {vulns.length === 0 ? (
        <text fg={colors.textMuted}>No findings yet</text>
      ) : (
        <>
          {visible.map((v) => (
            <box key={v.id} flexDirection="row" gap={1}>
              <text fg={colors.primary}>+</text>
              <text fg={getSeverityColor(colors, v.severity)}>
                {(v.type || "FINDING").toUpperCase()}
              </text>
              <text fg={colors.textMuted}>{truncatePath(v.endpoint || "", 14)}</text>
            </box>
          ))}
          {remaining > 0 && <text fg={colors.textMuted}>... +{remaining} more</text>}
        </>
      )}
    </box>
  );
}

function getSeverityColor(colors: ThemeColors, severity: VerifiedVuln["severity"]): RGBA {
  switch (severity) {
    case "critical":
      return colors.error;
    case "high":
      return colors.tierRisky;
    case "medium":
      return colors.warning;
    case "low":
      return colors.accent;
    default:
      return colors.textMuted;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}
