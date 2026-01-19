/**
 * Status Bar Component
 *
 * Bottom status indicator showing running state and model info.
 */

import { RGBA } from "@opentui/core";

// Colors
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);

export type ChatStatus = "idle" | "running" | "waiting" | "done";

interface StatusBarProps {
  status: ChatStatus;
  modelName?: string;
  tokenCount?: { input: number; output: number };
}

/**
 * Format token count for display (e.g., "1.5K")
 */
function formatTokenCount(count: number): string {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  } else if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
}

/**
 * Get status indicator character and color
 */
function getStatusIndicator(status: ChatStatus): { char: string; color: RGBA } {
  switch (status) {
    case "running":
      return { char: "■", color: greenAccent };
    case "waiting":
      return { char: "■", color: yellowText };
    case "done":
      return { char: "■", color: dimText };
    case "idle":
    default:
      return { char: "■", color: dimText };
  }
}

/**
 * Get status label
 */
function getStatusLabel(status: ChatStatus): string {
  switch (status) {
    case "running":
      return "Running";
    case "waiting":
      return "Waiting";
    case "done":
      return "Done";
    case "idle":
    default:
      return "Ready";
  }
}

export function StatusBar({ status, modelName, tokenCount }: StatusBarProps) {
  const indicator = getStatusIndicator(status);
  const label = getStatusLabel(status);

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
      width="100%"
    >
      {/* Left: Status */}
      <box flexDirection="row" gap={1}>
        <text fg={indicator.color}>{indicator.char}</text>
        <text fg={creamText}>{label}</text>
      </box>

      {/* Right: Model and tokens */}
      <box flexDirection="row" gap={2}>
        {tokenCount && (tokenCount.input > 0 || tokenCount.output > 0) && (
          <text fg={dimText}>
            {formatTokenCount(tokenCount.input)}/{formatTokenCount(tokenCount.output)}
          </text>
        )}
        {modelName && (
          <text fg={dimText}>{modelName}</text>
        )}
      </box>
    </box>
  );
}

export default StatusBar;
