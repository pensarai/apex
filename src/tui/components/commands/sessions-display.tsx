import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import os from "os";
import { exec } from "child_process";
import { rmSync, existsSync } from "fs";
import { join } from "path";
import { listSessions, getSession } from "../../../core/agent/sessions";
import type { Session } from "../../../core/agent/sessions";
import { getMessages, type Message } from "../../../core/messages";
import AgentDisplay from "../agent-display";

export default function SessionsDisplay({
  closeSessions,
}: {
  closeSessions: () => void;
}) {
  const [sessionIds, setSessionIds] = useState<string[]>([]);
  const [sessions, setSessions] = useState<(Session | null)[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [openMessages, setOpenMessages] = useState<boolean>(false);

  useEffect(() => {
    async function loadSessions() {
      setLoading(true);
      try {
        const ids = listSessions();
        setSessionIds(ids);

        // Load session details for each ID
        const sessionDetails = ids.map((id) => getSession(id));
        setSessions(sessionDetails);
      } catch (error) {
        console.error("Error loading sessions:", error);
      } finally {
        setLoading(false);
      }
    }

    loadSessions();
  }, []);

  function openFolder() {
    const session = sessions[selectedIndex];
    if (!session) return;

    exec(`open "${session.rootPath}"`, (error) => {
      if (error) {
        console.error("Error opening folder:", error);
        setStatusMessage("Error opening folder");
        setTimeout(() => setStatusMessage(""), 2000);
      } else {
        setTimeout(() => setStatusMessage(""), 2000);
      }
    });
  }

  function openReport() {
    const session = sessions[selectedIndex];
    if (!session) return;

    const reportPath = join(session.rootPath, "pentest-report.md");

    if (!existsSync(reportPath)) {
      setStatusMessage("Report not found");
      setTimeout(() => setStatusMessage(""), 2000);
      return;
    }

    exec(`open "${reportPath}"`, (error) => {
      if (error) {
        console.error("Error opening report:", error);
        setStatusMessage("Error opening report");
        setTimeout(() => setStatusMessage(""), 2000);
      } else {
        setTimeout(() => setStatusMessage(""), 2000);
      }
    });
  }

  function deleteSession() {
    const session = sessions[selectedIndex];
    if (!session) return;

    try {
      rmSync(session.rootPath, { recursive: true, force: true });
      setStatusMessage("Session deleted");
      setTimeout(() => setStatusMessage(""), 2000);

      // Reload sessions
      const ids = listSessions();
      setSessionIds(ids);
      const sessionDetails = ids.map((id) => getSession(id));
      setSessions(sessionDetails);

      // Adjust selected index if needed
      if (selectedIndex >= ids.length && ids.length > 0) {
        setSelectedIndex(ids.length - 1);
      } else if (ids.length === 0) {
        setSelectedIndex(0);
      }
    } catch (error) {
      console.error("Error deleting session:", error);
      setStatusMessage("Error deleting session");
      setTimeout(() => setStatusMessage(""), 2000);
    }
  }

  useKeyboard((key) => {
    // Escape - Close message display or sessions display
    if (key.name === "escape") {
      if (openMessages) {
        setOpenMessages(false);
      } else {
        closeSessions();
      }
      return;
    }

    // O - Open messages/agent display
    if (key.name === "o" && sessionIds.length > 0 && !openMessages) {
      setOpenMessages(true);
      return;
    }

    // Arrow Up - Previous session
    if (key.name === "up" && sessionIds.length > 0 && !openMessages) {
      setSelectedIndex((prev) => (prev > 0 ? prev - 1 : sessionIds.length - 1));
      return;
    }

    // Arrow Down - Next session
    if (key.name === "down" && sessionIds.length > 0 && !openMessages) {
      setSelectedIndex((prev) => (prev < sessionIds.length - 1 ? prev + 1 : 0));
      return;
    }

    // F - Open folder
    if (key.name === "f" && sessionIds.length > 0 && !openMessages) {
      openFolder();
      return;
    }

    // R - Open report
    if (key.name === "r" && sessionIds.length > 0 && !openMessages) {
      openReport();
      return;
    }

    // D - Delete session (with confirmation)
    if (key.name === "d" && sessionIds.length > 0 && !openMessages) {
      deleteSession();
      return;
    }
  });

  return (
    <>
      {openMessages && (
        <SessionMessagesDisplay session={sessions[selectedIndex]!} />
      )}
      {!openMessages && (
        <box
          alignItems="center"
          justifyContent="center"
          flexDirection="column"
          width="100%"
          maxHeight="100%"
          flexGrow={1}
          flexShrink={1}
          overflow="hidden"
          gap={1}
        >
          <box flexDirection="column" width="80%" gap={1}>
            <text fg="green">Sessions</text>
            <text fg="white">
              Sessions folder:{" "}
              <span fg="gray">~{os.homedir()}/.pensar/executions</span>
            </text>

            {loading && <text fg="gray">Loading sessions...</text>}

            {!loading && sessionIds.length === 0 && (
              <text fg="yellow">No sessions found</text>
            )}

            {!loading && sessionIds.length > 0 && (
              <scrollbox
                style={{
                  rootOptions: {
                    width: "100%",
                    maxWidth: "100%",
                    flexGrow: 1,
                    flexShrink: 1,
                    overflow: "hidden",
                    borderColor: "green",
                    focusedBorderColor: "green",
                    border: true,
                  },
                  wrapperOptions: {
                    overflow: "hidden",
                  },
                  contentOptions: {
                    gap: 1,
                    flexGrow: 1,
                    flexDirection: "column",
                  },
                  scrollbarOptions: {
                    trackOptions: {
                      foregroundColor: "green",
                    },
                  },
                }}
                focused
              >
                {sessions.map((session, index) => {
                  const isSelected = index === selectedIndex;
                  const sessionId = sessionIds[index];

                  if (!session) {
                    return (
                      <box key={sessionId} flexDirection="row" gap={1}>
                        <text fg={isSelected ? "green" : "gray"}>
                          {isSelected ? ">" : " "} {sessionId || "Unknown"}
                        </text>
                        <text fg="red">(metadata not found)</text>
                      </box>
                    );
                  }

                  const startDate = new Date(session.startTime);
                  const formattedDate = startDate.toLocaleString();

                  return (
                    <box
                      onMouseDown={() => setSelectedIndex(index)}
                      key={session.id}
                      flexDirection="column"
                      gap={0}
                      padding={1}
                    >
                      <text fg={isSelected ? "green" : "white"}>
                        {isSelected ? "▶ " : "  "} {session.id}
                      </text>
                      <box paddingLeft={1} flexDirection="column" gap={0}>
                        <text paddingLeft={4} fg="gray">
                          {"  "}Target: {session.target}
                        </text>
                        <text paddingLeft={4} fg="gray">
                          {"  "}Objective: {session.objective}
                        </text>
                        <text paddingLeft={4} fg="gray">
                          {"  "}Started: {formattedDate}
                        </text>
                        <text paddingLeft={4} fg="gray">
                          {"  "}Path: {session.rootPath}
                        </text>
                      </box>
                    </box>
                  );
                })}
              </scrollbox>
            )}

            {sessionIds.length > 0 && (
              <box
                flexDirection="column"
                width="100%"
                gap={1}
                border={true}
                borderColor="green"
                padding={1}
              >
                <text fg="white">Actions for selected session:</text>
                <box flexDirection="row" gap={2}>
                  <text fg="green" onMouseDown={openReport}>
                    [O] Open Session
                  </text>
                  <text fg="green" onMouseDown={openFolder}>
                    [F] Open Folder
                  </text>
                  <text fg="green" onMouseDown={openReport}>
                    [R] Open Report
                  </text>

                  <text fg="red" onMouseDown={deleteSession}>
                    [D] Delete
                  </text>
                </box>
                {statusMessage && <text fg="yellow">{statusMessage}</text>}
              </box>
            )}

            <box flexDirection="row" width="100%" gap={1}>
              <text fg="gray">
                <span fg="green">[↑↓]</span> Navigate ·{" "}
                <span fg="green">[O]</span> Open Messages ·{" "}
                <span fg="green">[ESC]</span> Close
              </text>
            </box>
          </box>
        </box>
      )}
    </>
  );
}

function SessionMessagesDisplay({ session }: { session: Session }) {
  const [messages, setMessages] = useState<Message[]>([]);

  useEffect(() => {
    try {
      setMessages(getMessages(session));
    } catch (error) {
      console.error("Error loading messages:", error);
    }
  }, [session]);

  return <AgentDisplay messages={messages} />;
}
