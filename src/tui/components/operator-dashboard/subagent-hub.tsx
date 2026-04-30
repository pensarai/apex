/**
 * Subagent Hub Dialog
 *
 * Dialog showing all subagent sessions in a scrollable,
 * keyboard-navigable list. Uses the standard Dialog + DialogLayout pattern.
 */

import React, { useState, useEffect, useRef, memo } from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";

import { useTheme } from "../../theme";
import { useDimensions } from "../../context/dimensions";
import { AsciiSpinner } from "../shared/ascii-spinner";
import { scrollToIndex } from "../../utils/scroll";
import { getToolDisplayLabel } from "../shared/tool-registry";
import { SUBAGENT_STATUS_ORDER, type SubagentSession } from "./subagent-state";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function sortSessions(sessions: SubagentSession[]): SubagentSession[] {
  return [...sessions].sort((a, b) => {
    const statusDiff =
      SUBAGENT_STATUS_ORDER[a.status] - SUBAGENT_STATUS_ORDER[b.status];
    if (statusDiff !== 0) return statusDiff;
    return a.spawnedAt.getTime() - b.spawnedAt.getTime();
  });
}

function formatElapsed(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

function countToolCalls(session: SubagentSession): number {
  return session.messages.filter((m) => m.role === "tool").length;
}

/** Extract a one-line summary of the most recent activity. */
function getLastActivity(session: SubagentSession, maxLen: number): string {
  const msgs = session.messages;
  if (msgs.length === 0) return "";

  // Walk backwards to find the most recent meaningful content
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.role === "tool" && m.toolName) {
      const isPending = m.status === "pending" || m.status === "streaming";
      const icon = isPending
        ? "\u25cb"
        : m.status === "error"
          ? "\u2717"
          : "\u2713";
      const label = getToolDisplayLabel(
        m.toolName,
        (m.args as Record<string, unknown>) ?? {},
      );
      const line = `${icon} ${label}`;
      return line.length > maxLen ? line.slice(0, maxLen - 1) + "\u2026" : line;
    }
    if (
      m.role === "assistant" &&
      typeof m.content === "string" &&
      m.content.trim()
    ) {
      // Get the last non-empty line
      const lines = m.content.trim().split("\n");
      const last = lines[lines.length - 1].trim();
      if (last) {
        return last.length > maxLen
          ? last.slice(0, maxLen - 1) + "\u2026"
          : last;
      }
    }
  }
  return "";
}

// ---------------------------------------------------------------------------
// SubagentHubCard
// ---------------------------------------------------------------------------

interface SubagentHubCardProps {
  session: SubagentSession;
  focused: boolean;
}

const SubagentHubCard = memo(function SubagentHubCard({
  session,
  focused,
}: SubagentHubCardProps) {
  const { colors } = useTheme();
  const { width: termWidth } = useDimensions();

  const toolCalls = countToolCalls(session);
  const now = Date.now();
  const elapsed =
    (session.completedAt ?? new Date(now)).getTime() -
    session.spawnedAt.getTime();

  const prefix = focused ? "\u25b8 " : "  ";
  const nameColor = focused ? colors.primary : colors.text;

  // Status-dependent rendering
  let statusIcon: React.ReactNode;
  let timeLabel: string;
  switch (session.status) {
    case "running":
      statusIcon = <AsciiSpinner label="" fg={colors.warning} />;
      timeLabel = `running ${formatElapsed(now - session.spawnedAt.getTime())}`;
      break;
    case "completed":
      statusIcon = <text fg={colors.success} content={"\u2713 "} />;
      timeLabel = `completed in ${formatElapsed(elapsed)}`;
      break;
    case "failed":
      statusIcon = <text fg={colors.error} content={"\u2717 "} />;
      timeLabel = `failed after ${formatElapsed(elapsed)}`;
      break;
    case "cancelled":
      statusIcon = <text fg={colors.textMuted} content={"\u25cb "} />;
      timeLabel = `cancelled after ${formatElapsed(elapsed)}`;
      break;
  }

  const toolLabel = `${toolCalls} tool call${toolCalls !== 1 ? "s" : ""}`;
  // Max width for the activity line: dialog width minus padding/indent
  const activityMaxLen = Math.max(30, termWidth - 16);
  const lastActivity = getLastActivity(session, activityMaxLen);

  return (
    <box flexDirection="column">
      {/* Line 1: prefix + status icon + name */}
      <box flexDirection="row">
        <text fg={focused ? colors.primary : colors.text} content={prefix} />
        {statusIcon}
        <text fg={nameColor} content={session.name} />
      </box>

      {/* Line 2: indented stats */}
      <box flexDirection="row" paddingLeft={4}>
        <text
          fg={colors.textMuted}
          content={`${toolLabel} \u00b7 ${timeLabel}`}
        />
      </box>

      {/* Line 3: last activity (always rendered to keep card height stable) */}
      <box flexDirection="row" paddingLeft={4} height={1} overflow="hidden">
        <text fg={colors.textMuted} content={lastActivity || " "} />
      </box>
    </box>
  );
});

// ---------------------------------------------------------------------------
// SubagentHub
// ---------------------------------------------------------------------------

export interface SubagentHubProps {
  sorted: SubagentSession[];
  onSelect: (id: string) => void;
}

export const SubagentHub = memo(function SubagentHub({
  sorted,
  onSelect,
}: SubagentHubProps) {
  const { colors } = useTheme();

  const [focusedIndex, setFocusedIndex] = useState(0);
  const scrollboxRef = useRef<ScrollBoxRenderable | null>(null);

  useEffect(() => {
    if (sorted.length === 0) {
      setFocusedIndex(0);
    } else if (focusedIndex >= sorted.length) {
      setFocusedIndex(sorted.length - 1);
    }
  }, [sorted.length, focusedIndex]);

  useEffect(() => {
    scrollToIndex(scrollboxRef.current, focusedIndex, sorted, (s) => s.id);
  }, [focusedIndex, sorted]);

  // Keyboard navigation (Escape is handled by DialogProvider / SubagentDialog)
  useKeyboard((key) => {
    if (sorted.length === 0) return;

    if (key.name === "up" || key.raw === "k") {
      key.preventDefault?.();
      setFocusedIndex((prev) => Math.max(0, prev - 1));
      return;
    }

    if (key.name === "down" || key.raw === "j") {
      key.preventDefault?.();
      setFocusedIndex((prev) => Math.min(sorted.length - 1, prev + 1));
      return;
    }

    if (key.name === "return") {
      key.preventDefault?.();
      const session = sorted[focusedIndex];
      if (session) {
        onSelect(session.id);
      }
      return;
    }
  });

  return (
    <box flexDirection="column" width="100%" flexGrow={1}>
      {/* Card list */}
      {sorted.length === 0 ? (
        <box flexGrow={1} alignItems="center" justifyContent="center">
          <text fg={colors.textMuted} content="No agents yet" />
        </box>
      ) : (
        <scrollbox
          ref={scrollboxRef}
          style={{
            rootOptions: { flexGrow: 1, width: "100%" },
            contentOptions: {
              flexDirection: "column",
              gap: 1,
              paddingTop: 1,
              paddingBottom: 1,
            },
          }}
          stickyScroll={false}
          focused={true}
        >
          {sorted.map((session, idx) => (
            <box key={session.id} id={session.id}>
              <SubagentHubCard
                session={session}
                focused={idx === focusedIndex}
              />
            </box>
          ))}
        </scrollbox>
      )}
    </box>
  );
});
