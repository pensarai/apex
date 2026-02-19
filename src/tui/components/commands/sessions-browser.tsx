/**
 * Sessions Browser - Full-page component for browsing and opening previous sessions.
 * Accessed via /sessions (alias: /s).
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { exec } from "child_process";
import { existsSync } from "fs";
import { RGBA, ScrollBoxRenderable } from "@opentui/core";
import { scrollToIndex } from "../../utils/scroll";
import { useRoute } from "../../context/route";
import { useSession } from "../../context/session";
import { useFocus } from "../../context/focus";
import { Storage } from "../../../core/storage";
import {
  useSessionsList,
  formatRelativeTime,
  type EnrichedSession,
} from "../../hooks/use-sessions-list";

// Design system colors
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

export default function SessionsBrowser() {
  const route = useRoute();
  const { load: loadSession } = useSession();
  const { refocusPrompt } = useFocus();

  const {
    groupedSessions,
    visualOrderSessions,
    totalCount,
    loading,
    searchTerm,
    setSearchTerm,
    deleteSession,
    reload,
  } = useSessionsList();

  const [selectedIndex, setSelectedIndex] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const scroll = useRef<ScrollBoxRenderable>(null);

  // Clamp selected index when list changes
  useEffect(() => {
    if (
      visualOrderSessions.length > 0 &&
      selectedIndex >= visualOrderSessions.length
    ) {
      setSelectedIndex(visualOrderSessions.length - 1);
    } else if (visualOrderSessions.length === 0) {
      setSelectedIndex(0);
    }
  }, [visualOrderSessions.length, selectedIndex]);

  const showStatus = useCallback((msg: string) => {
    setStatusMessage(msg);
    setTimeout(() => setStatusMessage(""), 2000);
  }, []);

  const openSession = useCallback(
    async (session: EnrichedSession, asOperator: boolean) => {
      const loaded = await loadSession(session.id);
      if (!loaded) {
        showStatus("Error loading session");
        return;
      }
      route.navigate({
        type: "session",
        sessionId: session.id,
        isResume: true,
        openAsOperator: asOperator || undefined,
      });
    },
    [loadSession, route, showStatus],
  );

  const openReport = useCallback(
    async (session: EnrichedSession) => {
      const reportPath = await Storage.locate(
        [session.id, "pentest-report"],
        ".md",
      );
      if (!existsSync(reportPath)) {
        showStatus("Report not found");
        return;
      }
      exec(`open "${reportPath}"`, (error) => {
        if (error) showStatus("Error opening report");
      });
    },
    [showStatus],
  );

  useKeyboard(async (key) => {
    // Escape - go home
    if (key.name === "escape") {
      refocusPrompt();
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Enter - open session in original mode
    if (key.name === "return" && visualOrderSessions.length > 0) {
      key.preventDefault();
      const selected = visualOrderSessions[selectedIndex];
      if (selected) await openSession(selected, false);
      return;
    }

    // O - open as operator
    if (
      (key.name === "o" || key.name === "O") &&
      !key.ctrl &&
      !key.meta &&
      visualOrderSessions.length > 0
    ) {
      const selected = visualOrderSessions[selectedIndex];
      if (selected) await openSession(selected, true);
      return;
    }

    // R - open report
    if (
      (key.name === "r" || key.name === "R") &&
      !key.ctrl &&
      !key.meta &&
      visualOrderSessions.length > 0
    ) {
      const selected = visualOrderSessions[selectedIndex];
      if (selected) await openReport(selected);
      return;
    }

    // Ctrl+D - delete session
    if (key.ctrl && key.name === "d" && visualOrderSessions.length > 0) {
      const selected = visualOrderSessions[selectedIndex];
      if (selected) {
        await deleteSession(selected.id);
        showStatus("Session deleted");
      }
      return;
    }

    // Up
    if (key.name === "up" && visualOrderSessions.length > 0) {
      const newIndex =
        selectedIndex > 0 ? selectedIndex - 1 : visualOrderSessions.length - 1;
      setSelectedIndex(newIndex);
      scrollToIndex(scroll.current, newIndex, visualOrderSessions, (s) => s.id);
      return;
    }

    // Down
    if (key.name === "down" && visualOrderSessions.length > 0) {
      const newIndex =
        selectedIndex < visualOrderSessions.length - 1 ? selectedIndex + 1 : 0;
      setSelectedIndex(newIndex);
      scrollToIndex(scroll.current, newIndex, visualOrderSessions, (s) => s.id);
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

  if (totalCount === 0) {
    return (
      <box flexDirection="column" padding={2} gap={1} width="100%">
        <text fg={creamText}>Sessions</text>
        <text fg={dimText}>No sessions found.</text>
        <text fg={dimText}>Start a new session with /pentest or /operator</text>
        <text fg={dimText}>Press Esc to go back</text>
      </box>
    );
  }

  return (
    <box flexDirection="column" padding={2} gap={1} width="100%" flexGrow={1}>
      {/* Header */}
      <box flexDirection="column" flexShrink={0}>
        <text fg={creamText}>Sessions</text>
        <text fg={dimText}>Browse and reopen previous pentest sessions</text>
      </box>

      {/* Search */}
      <box
        flexShrink={0}
        width="100%"
        border={["left"]}
        borderColor={greenAccent}
        backgroundColor="transparent"
      >
        <input
          paddingLeft={1}
          backgroundColor="transparent"
          placeholder="Search sessions..."
          value={searchTerm}
          onInput={setSearchTerm}
          focused
        />
      </box>

      {/* Session list */}
      <box flexDirection="column" gap={1} flexGrow={1} overflow="hidden">
        {visualOrderSessions.length === 0 ? (
          <box paddingLeft={2}>
            <text fg={dimText}>No sessions found.</text>
          </box>
        ) : (
          <scrollbox
            ref={scroll}
            scrollbarOptions={{ visible: false }}
            style={{
              rootOptions: {
                width: "100%",
                flexGrow: 1,
                flexShrink: 1,
                overflow: "hidden",
              },
              wrapperOptions: { overflow: "hidden" },
              contentOptions: { gap: 2, flexDirection: "column" },
            }}
          >
            {groupedSessions.map((group) => (
              <box key={group.date} flexDirection="column" gap={1}>
                <text fg={greenAccent}>{group.date}</text>
                {group.sessions.map((session) => {
                  const isSelected = session.index === selectedIndex;
                  const age = formatRelativeTime(session.time.updated);
                  const mode = session.config?.mode || "auto";
                  const modeBadge =
                    mode === "operator" ? "[operator]" : "[auto]";
                  const findingsText =
                    session.findingsCount > 0
                      ? `${session.findingsCount} finding${session.findingsCount > 1 ? "s" : ""}`
                      : "";

                  return (
                    <box
                      id={session.id}
                      key={session.id}
                      backgroundColor="transparent"
                      border={isSelected ? ["left"] : undefined}
                      borderColor={isSelected ? greenAccent : undefined}
                      paddingLeft={isSelected ? 1 : 2}
                      flexDirection="row"
                      justifyContent="space-between"
                      width="100%"
                    >
                      <box flexDirection="row" gap={1}>
                        <text fg={isSelected ? greenAccent : creamText}>
                          {isSelected ? "▸ " : "  "}
                          {session.name}
                        </text>
                        <text fg={mode === "operator" ? greenAccent : dimText}>
                          {modeBadge}
                        </text>
                        {findingsText ? (
                          <text fg={dimText}>{findingsText}</text>
                        ) : null}
                      </box>
                      <text fg={dimText}>{age}</text>
                    </box>
                  );
                })}
              </box>
            ))}
          </scrollbox>
        )}
      </box>

      {/* Footer */}
      <box flexDirection="row" gap={1} flexShrink={0}>
        <text fg={dimText}>
          <span fg={greenAccent}>[Enter]</span> Open{"  "}
          <span fg={greenAccent}>[O]</span> Operator{"  "}
          <span fg={greenAccent}>[R]</span> Report{"  "}
          <span fg={greenAccent}>[Ctrl+D]</span> Delete{"  "}
          <span fg={greenAccent}>[Esc]</span> Back
        </text>
      </box>

      {/* Status */}
      {statusMessage && <text fg={greenAccent}>{statusMessage}</text>}
    </box>
  );
}
