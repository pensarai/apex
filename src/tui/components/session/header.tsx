/**
 * Session Header Component
 *
 * Displays session info, mode, tokens, and stage at the top of the session view.
 * Layout: MODE | target URL | endpoints found | findings documented | tokens | tool calls
 */

import { colors, formatTokenCount, getTierColor } from "../../theme";
import type { OperatorMode, OperatorStage, PermissionTier } from "../../../core/operator";

export interface HeaderProps {
  /** Session mode */
  mode: "chat" | "operator";
  /** Target URL or hostname */
  target?: string;
  /** Session name */
  sessionName?: string;
  /** Model name for display */
  modelName?: string;
  /** Token usage */
  tokenUsage?: { inputTokens: number; outputTokens: number };
  /** Operator-specific: current mode */
  operatorMode?: OperatorMode;
  /** Operator-specific: current stage */
  currentStage?: OperatorStage;
  /** Operator-specific: auto-approve tier */
  autoApproveTier?: PermissionTier;
  /** Operator-specific: approval stats */
  stats?: { approved: number; denied: number };
  /** Number of endpoints discovered */
  endpointsCount?: number;
  /** Number of findings documented */
  findingsCount?: number;
  /** Number of tool calls made */
  toolCallsCount?: number;
}

/**
 * Session header - displays context info and status
 * Layout: MODE | target URL | endpoints | findings   ...   tokens | tool calls
 */
export function Header({
  mode,
  target,
  sessionName,
  modelName,
  tokenUsage,
  operatorMode,
  currentStage,
  autoApproveTier,
  stats,
  endpointsCount = 0,
  findingsCount = 0,
  toolCallsCount = 0,
}: HeaderProps) {
  // Get mode display
  const getModeDisplay = () => {
    if (mode === "chat") {
      return { text: "CHAT", color: colors.cyanAccent };
    }
    switch (operatorMode) {
      case "plan":
        return { text: "PLAN", color: colors.yellowText };
      case "auto":
        return { text: "AUTO", color: colors.greenAccent };
      case "manual":
      default:
        return { text: "MANUAL", color: colors.creamText };
    }
  };

  const modeDisplay = getModeDisplay();
  const totalTokens = tokenUsage
    ? tokenUsage.inputTokens + tokenUsage.outputTokens
    : 0;

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
    >
      {/* Left side: MODE | target | endpoints | findings */}
      <box flexDirection="row" gap={1}>
        {/* Mode indicator */}
        <text fg={modeDisplay.color}>
          {modeDisplay.text}
        </text>

        {/* Target URL */}
        {target && (
          <>
            <text fg={colors.dimText}>│</text>
            <text fg={colors.creamText}>{target}</text>
          </>
        )}

        {/* Endpoints count */}
        {endpointsCount > 0 && (
          <>
            <text fg={colors.dimText}>│</text>
            <text fg={colors.toolColor}>{endpointsCount}</text>
            <text fg={colors.dimText}>endpoints</text>
          </>
        )}

        {/* Findings count */}
        {findingsCount > 0 && (
          <>
            <text fg={colors.dimText}>│</text>
            <text fg={colors.greenAccent}>{findingsCount}</text>
            <text fg={colors.dimText}>findings</text>
          </>
        )}

        {/* Auto-approve tier indicator */}
        {autoApproveTier && mode === "operator" && (
          <>
            <text fg={colors.dimText}>│</text>
            <text fg={getTierColor(autoApproveTier)}>T{autoApproveTier}</text>
          </>
        )}
      </box>

      {/* Right side: model | tokens | tool calls */}
      <box flexDirection="row" gap={1}>
        {/* Tool calls count */}
        {toolCallsCount > 0 && (
          <>
            <text fg={colors.dimText}>│</text>
            <text fg={colors.toolColor}>{toolCallsCount}</text>
            <text fg={colors.dimText}>tool calls</text>
          </>
        )}
      </box>
    </box>
  );
}

export default Header;
