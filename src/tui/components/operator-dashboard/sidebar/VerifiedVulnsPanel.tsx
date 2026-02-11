/**
 * Verified Vulns Panel - Shows confirmed findings with POCs
 */

import type { VerifiedVuln } from "../types";
import { useColors, type ThemeColors } from "../../../theme";

interface VerifiedVulnsPanelProps {
  vulns: VerifiedVuln[];
  maxVisible?: number;
}

export function VerifiedVulnsPanel({ vulns, maxVisible = 5 }: VerifiedVulnsPanelProps) {
  const colors = useColors();
  const { creamText, dimText, greenAccent } = colors;
  const visible = vulns.slice(0, maxVisible);
  const remaining = vulns.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>
        Verified Vulns {vulns.length > 0 && <span fg={greenAccent}>({vulns.length})</span>}
      </text>

      {vulns.length === 0 ? (
        <text fg={dimText}>No findings yet</text>
      ) : (
        <>
          {visible.map((v) => (
            <box key={v.id} flexDirection="row" gap={1}>
              <text fg={greenAccent}>+</text>
              <text fg={getSeverityColor(v.severity, colors)}>{((v as any).type || (v as any).title || 'FINDING').toUpperCase()}</text>
              <text fg={dimText}>{truncatePath(v.endpoint || '', 14)}</text>
            </box>
          ))}
          {remaining > 0 && (
            <text fg={dimText}>... +{remaining} more</text>
          )}
        </>
      )}
    </box>
  );
}

function getSeverityColor(severity: VerifiedVuln['severity'], colors: ThemeColors) {
  switch (severity) {
    case "critical":
      return colors.redText;
    case "high":
      return colors.orangeText;
    case "medium":
      return colors.yellowText;
    case "low":
      return colors.toolColor;
    default:
      return colors.dimText;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}
