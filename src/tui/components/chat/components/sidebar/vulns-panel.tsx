/**
 * Vulnerabilities Panel
 *
 * Shows verified vulnerabilities with severity indicators.
 */

import { RGBA } from "@opentui/core";
import type { VerifiedVuln } from "../../../operator-dashboard/types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);
const purpleText = RGBA.fromInts(186, 104, 200, 255);

interface VulnsPanelProps {
  vulns: VerifiedVuln[];
  maxVisible?: number;
}

export function VulnsPanel({ vulns, maxVisible = 5 }: VulnsPanelProps) {
  const visible = vulns.slice(0, maxVisible);
  const remaining = vulns.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>
        Verified Vulnerabilities{" "}
        {vulns.length > 0 && (
          <span fg={greenAccent}>({vulns.length})</span>
        )}
      </text>

      {vulns.length === 0 ? (
        <text fg={dimText}>No vulnerabilities verified</text>
      ) : (
        <>
          {visible.map((vuln) => (
            <box key={vuln.id} flexDirection="column" gap={0}>
              <box flexDirection="row" gap={1}>
                <text fg={getSeverityColor(vuln.severity)}>
                  {getSeverityIndicator(vuln.severity)}
                </text>
                <text fg={creamText}>{vuln.type.toUpperCase()}</text>
              </box>
              <box marginLeft={2}>
                <text fg={dimText}>{truncate(vuln.endpoint, 30)}</text>
              </box>
              {vuln.summary && (
                <box marginLeft={2}>
                  <text fg={dimText}>{truncate(vuln.summary, 35)}</text>
                </box>
              )}
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

function getSeverityIndicator(severity: VerifiedVuln["severity"]): string {
  switch (severity) {
    case "critical":
      return "●●●●";
    case "high":
      return "●●●○";
    case "medium":
      return "●●○○";
    case "low":
      return "●○○○";
    case "info":
    default:
      return "○○○○";
  }
}

function getSeverityColor(severity: VerifiedVuln["severity"]) {
  switch (severity) {
    case "critical":
      return purpleText;
    case "high":
      return redText;
    case "medium":
      return orangeText;
    case "low":
      return yellowText;
    case "info":
    default:
      return dimText;
  }
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}

export default VulnsPanel;
