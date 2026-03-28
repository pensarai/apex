/**
 * Swarm Grid Component
 *
 * Compact grid view for pentest swarm sub-agents.
 * Shows agent cards with status, name, target, and last log line.
 * Supports keyboard navigation and expandable detail view.
 */

import { memo, useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme } from "../../theme";
import { AsciiSpinner } from "./ascii-spinner";
import type { SubagentLogEntry } from "../agent-display";

interface SwarmGridProps {
  subagentLogs: Record<string, SubagentLogEntry>;
  /** Whether the parent tool is still pending/streaming */
  isPending: boolean;
  /** Whether to show expanded logs */
  expandedLogs?: boolean;
}

/**
 * SwarmGrid — renders pentest swarm agents in a compact card-style layout
 * with a progress summary header.
 */
export const SwarmGrid = memo(function SwarmGrid({
  subagentLogs,
  isPending,
  expandedLogs = false,
}: SwarmGridProps) {
  const { colors } = useTheme();
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const [expandedAgentId, setExpandedAgentId] = useState<string | null>(null);

  const entries = useMemo(
    () => Object.entries(subagentLogs).sort(([a], [b]) => a.localeCompare(b)),
    [subagentLogs],
  );

  const total = entries.length;
  const completed = entries.filter(([, e]) => e.status === "completed").length;
  const failed = entries.filter(([, e]) => e.status === "failed").length;
  const pending = total - completed - failed;

  useKeyboard((key) => {
    if (total === 0) return;

    if (expandedAgentId) {
      if (key.name === "escape") {
        key.preventDefault();
        setExpandedAgentId(null);
        return;
      }
      return;
    }

    if (focusedIndex < 0) return;

    if (key.name === "up") {
      key.preventDefault();
      setFocusedIndex((i) => Math.max(0, i - 1));
      return;
    }
    if (key.name === "down") {
      key.preventDefault();
      setFocusedIndex((i) => Math.min(total - 1, i + 1));
      return;
    }
    if (key.name === "return") {
      key.preventDefault();
      const entry = entries[focusedIndex];
      if (entry) setExpandedAgentId(entry[0]);
      return;
    }
  });

  if (total === 0) return null;

  if (expandedAgentId) {
    const entry = subagentLogs[expandedAgentId];
    if (!entry) {
      setExpandedAgentId(null);
      return null;
    }
    return (
      <SwarmAgentDetail
        agentId={expandedAgentId}
        entry={entry}
        expandedLogs={expandedLogs}
      />
    );
  }

  return (
    <box flexDirection="column" marginLeft={0} marginTop={0}>
      {/* Progress summary header */}
      <box flexDirection="row" gap={1}>
        <text fg={colors.textMuted}>{"  ┌ "}</text>
        {isPending ? (
          <AsciiSpinner
            label={`Swarm: ${completed}/${total} complete`}
            fg={colors.warning}
          />
        ) : (
          <text fg={colors.success}>
            {"✓"} Swarm: {completed}/{total} complete
          </text>
        )}
        {failed > 0 && <text fg={colors.error}>· {failed} failed</text>}
        {pending > 0 && isPending && (
          <text fg={colors.textMuted}>· {pending} running</text>
        )}
      </box>

      {/* Agent cards */}
      {entries.map(([id, entry], idx) => (
        <SwarmAgentCard
          key={id}
          agentId={id}
          entry={entry}
          focused={idx === focusedIndex}
          compact={total > 5}
        />
      ))}

      <text fg={colors.textMuted}>{"  └─"}</text>
    </box>
  );
});

const SwarmAgentCard = memo(function SwarmAgentCard({
  agentId,
  entry,
  focused,
  compact,
}: {
  agentId: string;
  entry: SubagentLogEntry;
  focused: boolean;
  compact: boolean;
}) {
  const { colors } = useTheme();
  const isAgentPending = entry.status === "pending";
  const statusColor =
    entry.status === "completed"
      ? colors.success
      : entry.status === "failed"
        ? colors.error
        : colors.warning;
  const statusIcon =
    entry.status === "completed" ? "✓" : entry.status === "failed" ? "✗" : "◐";
  const displayLabel = entry.name ?? agentId;
  const lastLog =
    entry.logs.length > 0 ? entry.logs[entry.logs.length - 1] : undefined;
  const prefix = focused ? "  ├▸" : "  │ ";

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        <text fg={focused ? colors.primary : colors.textMuted}>{prefix} </text>
        {isAgentPending ? (
          <AsciiSpinner label={displayLabel} fg={statusColor} />
        ) : (
          <text>
            <span fg={statusColor}>{statusIcon}</span>
            <span fg={focused ? colors.text : colors.textMuted}>
              {` ${displayLabel}`}
            </span>
          </text>
        )}
      </box>
      {!compact && lastLog && (
        <text fg={colors.textMuted}>
          {"  │   "}
          {lastLog.length > 60 ? lastLog.slice(0, 57) + "..." : lastLog}
        </text>
      )}
    </box>
  );
});

const SwarmAgentDetail = memo(function SwarmAgentDetail({
  agentId,
  entry,
  expandedLogs,
}: {
  agentId: string;
  entry: SubagentLogEntry;
  expandedLogs: boolean;
}) {
  const { colors } = useTheme();
  const isAgentPending = entry.status === "pending";
  const statusColor =
    entry.status === "completed"
      ? colors.success
      : entry.status === "failed"
        ? colors.error
        : colors.warning;
  const statusIcon =
    entry.status === "completed" ? "✓" : entry.status === "failed" ? "✗" : "";
  const displayLabel = entry.name ?? agentId;
  const visibleLogs = expandedLogs ? entry.logs : entry.logs.slice(-15);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        <text fg={colors.textMuted}>{"  ┌ "}</text>
        {isAgentPending ? (
          <AsciiSpinner label={displayLabel} fg={colors.warning} />
        ) : (
          <text>
            <span fg={statusColor}>{statusIcon}</span>
            <span fg={colors.textMuted}>{` ${displayLabel}`}</span>
          </text>
        )}
        <text fg={colors.textMuted}> [Esc] back</text>
      </box>
      {visibleLogs.length > 0 && (
        <box marginLeft={0}>
          <text fg={colors.textMuted}>
            {"  │ "}
            {visibleLogs.join("\n  │ ")}
          </text>
        </box>
      )}
      <text fg={colors.textMuted}>{"  └─"}</text>
    </box>
  );
});

export default SwarmGrid;
