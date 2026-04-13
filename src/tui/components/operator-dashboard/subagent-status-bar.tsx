/**
 * Subagent Status Bar
 *
 * Compact, single-line status bar showing active subagent counts.
 * Appears between MessageList and QueuedMessages when subagents are
 * actively relevant (running, or recently completed while agent is busy).
 * Hides when all subagents are done and the agent is idle.
 */

import { memo } from "react";
import { useTheme } from "../../theme";
import { AsciiSpinner } from "../shared/ascii-spinner";
import type { SubagentSession } from "./subagent-state";

interface SubagentStatusBarProps {
  sessions: Map<string, SubagentSession>;
  agentStatus: string;
  onOpen: () => void;
}

export const SubagentStatusBar = memo(function SubagentStatusBar({
  sessions,
  agentStatus,
  onOpen,
}: SubagentStatusBarProps) {
  const { colors } = useTheme();

  if (sessions.size === 0) return null;

  let running = 0;
  let completed = 0;
  let failed = 0;
  let cancelled = 0;

  for (const session of sessions.values()) {
    if (session.status === "running") running++;
    else if (session.status === "completed") completed++;
    else if (session.status === "failed") failed++;
    else if (session.status === "cancelled") cancelled++;
  }

  const allDone = running === 0;

  // Hide the bar when all subagents are done and the agent is idle —
  // the subagents are historical at that point. User can still use Ctrl+A.
  if (allDone && agentStatus === "idle") return null;

  const total = sessions.size;

  // Build the count segments — omit categories with 0 count
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
    >
      {/* Left side: agent stats */}
      <box flexDirection="row">
        {allDone ? (
          <text fg={colors.success} content={`\u2713 ${total} agents`} />
        ) : (
          <AsciiSpinner label={`${total} agents`} />
        )}
        {parts.length > 0 && <text fg={colors.textMuted} content="  " />}
        {parts.map((part, i) => (
          <box key={part.label} flexDirection="row">
            {i > 0 && <text fg={colors.textMuted} content=" \u00b7 " />}
            <text fg={part.color} content={part.label} />
          </box>
        ))}
      </box>

      {/* Right side: keyboard shortcut hint */}
      <text fg={colors.textMuted} content="Ctrl+A view agents" />
    </box>
  );
});
