/**
 * Subagent Status Bar
 *
 * Compact, single-line status bar showing active subagent counts.
 * Appears between MessageList and QueuedMessages when subagents are
 * actively relevant. Hides once the main agent has moved on (produced
 * new output after all subagents finished).
 */

import { memo } from "react";
import { useTheme } from "../../theme";
import { AsciiSpinner } from "../shared";
import type { SubagentCounts } from "./subagent-state";

interface SubagentStatusBarProps {
  counts: SubagentCounts;
  /** Whether the main agent has produced new messages since subagents finished */
  agentMovedOn: boolean;
  onOpen: () => void;
}

export const SubagentStatusBar = memo(function SubagentStatusBar({
  counts,
  agentMovedOn,
  onOpen,
}: SubagentStatusBarProps) {
  const { colors } = useTheme();

  const { total, running, completed, failed, cancelled } = counts;
  if (total === 0) return null;

  const allDone = running === 0;

  // Hide once the main agent has moved on past the subagent work
  if (allDone && agentMovedOn) return null;

  const parts: Array<{ label: string; color: typeof colors.warning }> = [];
  if (running > 0)
    parts.push({ label: `${running} running`, color: colors.warning });
  if (completed > 0)
    parts.push({ label: `${completed} complete`, color: colors.success });
  if (failed > 0)
    parts.push({ label: `${failed} failed`, color: colors.error });
  if (cancelled > 0)
    parts.push({ label: `${cancelled} cancelled`, color: colors.textMuted });

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      paddingLeft={2}
      paddingRight={2}
      flexShrink={0}
      height={1}
      onMouseDown={onOpen}
    >
      {/* Left side: agent stats */}
      <box flexDirection="row">
        {allDone ? (
          <text
            fg={colors.textMuted}
            content={`${total} agent${total !== 1 ? "s" : ""}`}
          />
        ) : (
          <AsciiSpinner label={`${total} agent${total !== 1 ? "s" : ""}`} />
        )}
        {parts.length > 0 && <text fg={colors.textMuted} content="  " />}
        {parts.map((part, i) => (
          <box key={part.label} flexDirection="row">
            {i > 0 && <text fg={colors.textMuted} content={" \u00b7 "} />}
            <text fg={part.color} content={part.label} />
          </box>
        ))}
      </box>

      {/* Right side: keyboard shortcut hint */}
      <text fg={colors.textMuted} content="Ctrl+A view agents" />
    </box>
  );
});
