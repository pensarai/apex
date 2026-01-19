/**
 * Recent Sessions Component
 *
 * Displays a list of recent sessions with resume capability.
 * Arrow keys to select, Enter to resume.
 */

import { useState, useEffect } from "react";
import { RGBA } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { Session } from "../../../../core/session";

// Colors
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

interface RecentSessionsProps {
  sessions: Session.SessionInfo[];
  selectedIndex: number;
  onSelectIndex: (index: number) => void;
  onResume: (session: Session.SessionInfo) => void;
  focused?: boolean;
  maxVisible?: number;
}

export function RecentSessions({
  sessions,
  selectedIndex,
  onSelectIndex,
  onResume,
  focused = false,
  maxVisible = 5,
}: RecentSessionsProps) {
  useKeyboard((key) => {
    if (!focused || sessions.length === 0) return;

    if (key.name === "up") {
      onSelectIndex(Math.max(0, selectedIndex - 1));
      return;
    }
    if (key.name === "down") {
      onSelectIndex(Math.min(sessions.length - 1, selectedIndex + 1));
      return;
    }
    if (key.name === "return" && selectedIndex >= 0) {
      onResume(sessions[selectedIndex]);
      return;
    }
  });

  const visible = sessions.slice(0, maxVisible);

  if (sessions.length === 0) {
    return (
      <box flexDirection="column" gap={0}>
        <text fg={dimText}>Recent sessions</text>
        <text fg={dimText}>  No recent sessions</text>
      </box>
    );
  }

  return (
    <box flexDirection="column" gap={0}>
      <text fg={dimText}>Recent sessions</text>
      {visible.map((session, idx) => {
        const isSelected = focused && idx === selectedIndex;

        return (
          <box key={session.id} flexDirection="row" gap={0}>
            <text fg={greenAccent}>{isSelected ? "▌" : "│"}</text>
            <text fg={isSelected ? greenAccent : creamText}>
              {" "}{session.name || session.targets[0] || "Untitled"}
            </text>
          </box>
        );
      })}
      {sessions.length > maxVisible && (
        <text fg={dimText}>  +{sessions.length - maxVisible} more</text>
      )}
    </box>
  );
}

/**
 * Hook to load recent sessions
 */
export function useRecentSessions(limit: number = 5) {
  const [sessions, setSessions] = useState<Session.SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadSessions = async () => {
      try {
        const list: Session.SessionInfo[] = [];
        for await (const session of Session.list()) {
          list.push(session);
        }
        // Sort by updated time (most recent first)
        list.sort((a, b) => b.time.updated - a.time.updated);
        setSessions(list.slice(0, limit));
      } catch (error) {
        console.error("Failed to load sessions:", error);
      } finally {
        setLoading(false);
      }
    };

    loadSessions();
  }, [limit]);

  return { sessions, loading };
}

export default RecentSessions;
