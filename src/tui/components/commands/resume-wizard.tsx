/**
 * Resume Wizard - Select and resume a previous pentest session
 */

import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { existsSync, readdirSync } from "fs";
import { join } from "path";
import { RGBA } from "@opentui/core";
import { useRoute } from "../../context/route";
import { useSession } from "../../context/session";
import { useFocus } from "../../context/focus";
import { Session } from "../../../core/session";

// Design system colors (matching web-wizard, operator-dashboard, etc.)
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

interface EnrichedSession extends Session.SessionInfo {
  findingsCount: number;
  hasOperatorState: boolean;
}

function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days === 1) return "yesterday";
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

function countFindings(findingsPath: string): number {
  try {
    if (!existsSync(findingsPath)) return 0;
    return readdirSync(findingsPath).filter(f => f.endsWith(".json")).length;
  } catch {
    return 0;
  }
}

export default function ResumeWizard() {
  const [sessions, setSessions] = useState<EnrichedSession[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState<string>("");

  const route = useRoute();
  const { load: loadSession } = useSession();
  const { refocusCommandInput } = useFocus();

  // Load sessions with operator state on mount
  useEffect(() => {
    async function loadOperatorSessions() {
      setLoading(true);
      try {
        const enrichedSessions: EnrichedSession[] = [];

        for await (const session of Session.list()) {
          const statePath = join(session.rootPath, "operator-state.json");
          const hasOperatorState = existsSync(statePath);
          const findingsCount = countFindings(session.findingsPath);
          enrichedSessions.push({
            ...session,
            findingsCount,
            hasOperatorState,
          });
        }

        // Sort by last update time (newest first)
        enrichedSessions.sort((a, b) => b.time.updated - a.time.updated);

        // Limit to recent sessions (last 20)
        setSessions(enrichedSessions.slice(0, 20));
      } catch (error) {
        console.error("Error loading sessions:", error);
        setStatusMessage("Error loading sessions");
      } finally {
        setLoading(false);
      }
    }

    loadOperatorSessions();
  }, []);

  const resumeSession = async (session: EnrichedSession) => {
    try {
      const loaded = await loadSession(session.id);
      if (!loaded) {
        setStatusMessage("Error loading session");
        setTimeout(() => setStatusMessage(""), 2000);
        return;
      }

      route.navigate({
        type: "session",
        sessionId: session.id,
        isResume: true,
      });
    } catch (error) {
      console.error("Error resuming session:", error);
      setStatusMessage("Error resuming session");
      setTimeout(() => setStatusMessage(""), 2000);
    }
  };

  useKeyboard((key) => {
    if (key.name === "escape") {
      refocusCommandInput();
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (key.name === "up" && sessions.length > 0) {
      setSelectedIndex((i) => (i > 0 ? i - 1 : sessions.length - 1));
      return;
    }

    if (key.name === "down" && sessions.length > 0) {
      setSelectedIndex((i) => (i < sessions.length - 1 ? i + 1 : 0));
      return;
    }

    if (key.name === "return" && sessions.length > 0) {
      const selected = sessions[selectedIndex];
      if (selected) {
        resumeSession(selected);
      }
      return;
    }
  });

  if (loading) {
    return (
      <box flexDirection="column" padding={2} width="100%">
        <text fg={creamText}>Loading sessions...</text>
      </box>
    );
  }

  if (sessions.length === 0) {
    return (
      <box flexDirection="column" padding={2} gap={1} width="100%">
        <text fg={creamText}>Resume Pentest Session</text>
        <text fg={dimText}>No sessions found to resume.</text>
        <text fg={dimText}>Start a new session with /web or /operator</text>
        <text fg={dimText}>Press Esc to go back</text>
      </box>
    );
  }

  return (
    <box flexDirection="column" padding={2} gap={1} width="100%">
      {/* Header */}
      <text fg={creamText}>Resume Pentest Session</text>
      <text fg={dimText}>Select a session to continue where you left off</text>

      {/* Session List */}
      <box flexDirection="column" marginTop={1}>
        {sessions.map((session, index) => {
          const isSelected = index === selectedIndex;
          const age = formatRelativeTime(session.time.updated);
          const target = session.targets[0] || "No target";
          const findingsText = session.findingsCount > 0
            ? `${session.findingsCount} finding${session.findingsCount > 1 ? "s" : ""}`
            : "No findings";

          return (
            <box
              key={session.id}
              flexDirection="row"
              justifyContent="space-between"
              width="100%"
              border={isSelected ? ["left"] : undefined}
              borderColor={isSelected ? greenAccent : undefined}
              paddingLeft={isSelected ? 1 : 2}
            >
              <box flexDirection="row" gap={1}>
                <text fg={isSelected ? greenAccent : creamText}>
                  {isSelected ? "▸ " : "  "}{session.name}
                </text>
                {session.hasOperatorState && (
                  <text fg={greenAccent}>●</text>
                )}
              </box>
              <text fg={dimText}>
                {target} · {findingsText} · {age}
              </text>
            </box>
          );
        })}
      </box>

      {/* Footer */}
      <box marginTop={2} flexDirection="column">
        <text fg={dimText}>
          <span fg={greenAccent}>↑↓</span> Navigate  <span fg={greenAccent}>Enter</span> Resume  <span fg={greenAccent}>Esc</span> Cancel
        </text>
        <text fg={dimText}>
          <span fg={greenAccent}>●</span> = Has saved state (full context restore)
        </text>
      </box>

      {/* Status Message */}
      {statusMessage && (
        <text fg={greenAccent}>{statusMessage}</text>
      )}
    </box>
  );
}
