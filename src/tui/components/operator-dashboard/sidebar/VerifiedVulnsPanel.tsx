/**
 * Verified Vulns Panel - Shows confirmed findings with POCs
 */

import { RGBA } from "@opentui/core";
import type { VerifiedVuln } from "../types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);

interface VerifiedVulnsPanelProps {
  vulns: VerifiedVuln[];
  maxVisible?: number;
}

export function VerifiedVulnsPanel({ vulns, maxVisible = 5 }: VerifiedVulnsPanelProps) {
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
              <text fg={getSeverityColor(v.severity)}>{((v as any).type || (v as any).title || 'FINDING').toUpperCase()}</text>
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

function getSeverityColor(severity: VerifiedVuln['severity']) {
  switch (severity) {
    case "critical":
      return redText;
    case "high":
      return orangeText;
    case "medium":
      return yellowText;
    case "low":
      return blueText;
    default:
      return dimText;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}
