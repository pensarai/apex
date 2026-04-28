/**
 * Session Header Component
 *
 * Displays session info, mode, tokens, and stage at the top of the session view.
 * Layout: MODE | target URL | endpoints found | findings documented | tokens | tool calls
 */

import { useTheme } from "../../theme";
import type { OperatorMode, OperatorStage } from "../../../core/operator";
import { obfuscate } from "../../../core/obfuscation";

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
  /** Whether command approval is enabled */
  requireApproval?: boolean;
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
  requireApproval,
  stats,
  endpointsCount = 0,
  findingsCount = 0,
  toolCallsCount = 0,
}: HeaderProps) {
  const { colors } = useTheme();
  // Get mode display
  const getModeDisplay = () => {
    if (mode === "chat") {
      return { text: "CHAT", color: colors.secondary };
    }
    switch (operatorMode) {
      case "plan":
        return { text: "PLAN", color: colors.warning };
      case "auto":
        return { text: "AUTO", color: colors.primary };
      case "manual":
      default:
        return { text: "MANUAL", color: colors.text };
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
        <text fg={modeDisplay.color}>{modeDisplay.text}</text>

        {/* Target URL */}
        {target && (
          <>
            <text fg={colors.textMuted}>│</text>
            <text fg={colors.text}>{obfuscate(target)}</text>
          </>
        )}

        {/* Endpoints count */}
        {endpointsCount > 0 && (
          <>
            <text fg={colors.textMuted}>│</text>
            <text fg={colors.info}>{endpointsCount}</text>
            <text fg={colors.textMuted}>endpoints</text>
          </>
        )}

        {/* Findings count */}
        {findingsCount > 0 && (
          <>
            <text fg={colors.textMuted}>│</text>
            <text fg={colors.primary}>{findingsCount}</text>
            <text fg={colors.textMuted}>findings</text>
          </>
        )}

        {/* Approval status indicator */}
        {requireApproval !== undefined && mode === "operator" && (
          <>
            <text fg={colors.textMuted}>│</text>
            <text fg={requireApproval ? colors.warning : colors.primary}>
              {requireApproval ? "approval:on" : "approval:off"}
            </text>
          </>
        )}
      </box>

      {/* Right side: model | tokens | tool calls */}
      <box flexDirection="row" gap={1}>
        {/* Tool calls count */}
        {toolCallsCount > 0 && (
          <>
            <text fg={colors.textMuted}>│</text>
            <text fg={colors.info}>{toolCallsCount}</text>
            <text fg={colors.textMuted}>tool calls</text>
          </>
        )}
      </box>
    </box>
  );
}

export default Header;
