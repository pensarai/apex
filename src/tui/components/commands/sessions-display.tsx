import { useState, useEffect, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { exec } from "child_process";
import { existsSync } from "fs";
import { useRoute } from "../../context/route";
import { useSession } from "../../context/session";
import { useFocus } from "../../context/focus";
import { Session } from "../../../core/session";
import { Storage } from "../../../core/storage";
import { Dialog } from "../../context/dialog";
import { Renderable, ScrollBoxRenderable } from "@opentui/core";

interface SessionsDisplayProps {
  onClose: () => void;
}

export default function SessionsDisplay({ onClose }: SessionsDisplayProps) {
  const { refocusPrompt } = useFocus();
  const [sessions, setSessions] = useState<(Session.SessionInfo)[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const route = useRoute();
  const session = useSession();

  const scroll = useRef<ScrollBoxRenderable>(null);

  async function loadSessions() {
    setLoading(true);
    try {
      const _sessions = await Array.fromAsync(Session.list());
      setSessions(_sessions);
    } catch (error) {
      console.error("Error loading sessions:", error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSessions();
  }, []);

  async function openReport(sessionId: string) {
    const session = await Session.get(sessionId);
    const reportPath = await Storage.locate([session.id, "pentest-report"], ".md");

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


  function scrollToIndex(index: number, list: Session.SessionInfo[]) {
    if (!scroll.current || list.length === 0) return;

    const targetSession = list[index];
    if (!targetSession) return;

    // Find the target element by searching through date groups
    let target: Renderable | undefined;
    for (const group of scroll.current.getChildren()) {
      const found = group.getChildren().find(child => child.id === targetSession.id);
      if (found) {
        target = found;
        break;
      }
    }

    if (!target) return;

    // Calculate target's visual position relative to the scroll container
    const targetVisualY = target.y - scroll.current.y;
    const viewportHeight = scroll.current.height;
    const targetHeight = target.height || 1;

    // If first item, always scroll to top
    if (index === 0) {
      scroll.current.scrollTo(0);
      return;
    }

    // If last item, scroll to bottom
    if (index === list.length - 1) {
      scroll.current.scrollTo(Infinity);
      return;
    }

    // Check if target is below visible area (accounting for its height)
    if (targetVisualY + targetHeight > viewportHeight) {
      // Scroll down by the amount needed to bring target into view
      scroll.current.scrollBy(targetVisualY - viewportHeight + targetHeight + 1);
    }
    // Check if target is above visible area
    else if (targetVisualY < 0) {
      // Scroll up by the amount needed (targetVisualY is negative)
      scroll.current.scrollBy(targetVisualY);
    }
  }

  // Filter sessions based on search term
  const filteredSessions = sessions.filter(session => {
    if (!searchTerm) return true;
    const searchLower = searchTerm.toLowerCase();
    return (
      session.name.toLowerCase().includes(searchLower)
    );
  });

  // Group sessions by date (without indices first)
  const groupedSessionsRaw: { date: string; timestamp: number; sessions: Session.SessionInfo[] }[] = [];
  filteredSessions.forEach((session) => {
    const startDate = new Date(session.time.created);
    const dateStr = startDate.toLocaleDateString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });

    let group = groupedSessionsRaw.find(g => g.date === dateStr);
    if (!group) {
      group = { date: dateStr, timestamp: startDate.getTime(), sessions: [] };
      groupedSessionsRaw.push(group);
    }
    group.sessions.push(session);
  });

  // Sort groups by date (newest first)
  groupedSessionsRaw.sort((a, b) => b.timestamp - a.timestamp);

  // Sort sessions within each group by time (newest first)
  groupedSessionsRaw.forEach(group => {
    group.sessions.sort((a, b) =>
      new Date(b.time.created).getTime() - new Date(a.time.created).getTime()
    );
  });

  // Create flat list in visual order and assign indices
  const visualOrderSessions: Session.SessionInfo[] = [];
  groupedSessionsRaw.forEach(group => {
    visualOrderSessions.push(...group.sessions);
  });

  // Now create grouped sessions with correct visual indices
  const groupedSessions: { date: string; sessions: (Session.SessionInfo & { index: number })[] }[] = [];
  let visualIndex = 0;
  groupedSessionsRaw.forEach(rawGroup => {
    const group: { date: string; sessions: (Session.SessionInfo & { index: number })[] } = {
      date: rawGroup.date,
      sessions: []
    };
    rawGroup.sessions.forEach(session => {
      group.sessions.push({ ...session, index: visualIndex });
      visualIndex++;
    });
    groupedSessions.push(group);
  });

  // Clamp selectedIndex when list changes
  useEffect(() => {
    if (visualOrderSessions.length > 0 && selectedIndex >= visualOrderSessions.length) {
      setSelectedIndex(visualOrderSessions.length - 1);
    } else if (visualOrderSessions.length === 0) {
      setSelectedIndex(0);
    }
  }, [visualOrderSessions.length, selectedIndex]);

  async function deleteSession(sessionId: string) {
    try {
      await Session.remove({ sessionId });
      setStatusMessage("Session deleted");
      setTimeout(() => setStatusMessage(""), 2000);

      // Reload sessions
      await loadSessions();

      // Adjust selected index - use visualOrderSessions.length - 1 since one was deleted
      const newLength = visualOrderSessions.length - 1;
      if (selectedIndex >= newLength && newLength > 0) {
        setSelectedIndex(newLength - 1);
      } else if (newLength === 0) {
        setSelectedIndex(0);
      }
    } catch (error) {
      console.error("Error deleting session:", error);
      setStatusMessage("Error deleting session");
      setTimeout(() => setStatusMessage(""), 2000);
    }
  }

  useKeyboard(async (key) => {
    // Escape - Close sessions display
    if (key.name === "escape") {
      refocusPrompt();
      onClose();
      return;
    }

    // Enter - View existing session (load state from disk)
    if (key.name === "return" && visualOrderSessions.length > 0) {
      key.preventDefault();
      const currentSelection = visualOrderSessions[selectedIndex];
      if (!currentSelection) return;
      const _session = await session.load(currentSelection.id);
      if(!_session) {
        console.error("Error loading session");
        return;
      }
      refocusPrompt();
      onClose();
      route.navigate({
        type: "session",
        sessionId: _session.id,
        isResume: true // Load existing state, don't start new pentest
      });
      return;
    }

    // Arrow Up - Previous session
    if (key.name === "up" && visualOrderSessions.length > 0) {
      const newIndex = selectedIndex > 0 ? selectedIndex - 1 : visualOrderSessions.length - 1;
      setSelectedIndex(newIndex);
      scrollToIndex(newIndex, visualOrderSessions);
      return;
    }

    // Arrow Down - Next session
    if (key.name === "down" && visualOrderSessions.length > 0) {
      const newIndex = selectedIndex < visualOrderSessions.length - 1 ? selectedIndex + 1 : 0;
      setSelectedIndex(newIndex);
      scrollToIndex(newIndex, visualOrderSessions);
      return;
    }

    // R - Open report
    if (key.name === "r" && visualOrderSessions.length > 0) {
      const currentSelection = visualOrderSessions[selectedIndex];
      if (!currentSelection) return;
      openReport(currentSelection.id);
      return;
    }

    // Ctrl+D - Delete session
    if (key.ctrl && key.name === "d" && visualOrderSessions.length > 0) {
      const currentSelection = visualOrderSessions[selectedIndex];
      if (!currentSelection) return;
      await deleteSession(currentSelection.id);
      return;
    }
  });


  const handleClose = () => {
    refocusPrompt();
    onClose();
  };

  return (
    <Dialog size="large" onClose={handleClose}>
      <box
        flexDirection="column"
        padding={2}
        gap={2}
        width="100%"
      >
        {/* Header */}
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg="white">Sessions</text>
          <text fg="gray">esc to close</text>
        </box>

        {/* Search Input */}
        <box
          width="100%"
          border={["left"]}
          borderColor="green"
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

        {/* Sessions List */}
        {loading ? (
          <text fg="gray">Loading sessions...</text>
        ) : visualOrderSessions.length === 0 ? (
          <text fg="gray">No sessions found</text>
        ) : (
          <box flexDirection="column" gap={2} flexGrow={1} maxHeight={10} overflow="hidden">
            <scrollbox
              ref={scroll}
              scrollbarOptions={{ visible: false }}
              style={{
                rootOptions: {
                  maxHeight: 10,
                  width: "100%",
                  flexGrow: 1,
                  flexShrink: 1,
                  overflow: "hidden",
                },
                wrapperOptions: {
                  overflow: "hidden",
                },
                contentOptions: {
                  gap: 2,
                  flexDirection: "column",
                },
              }}
            >
              {groupedSessions.map((group) => (
                <box key={group.date} flexDirection="column" gap={1}>
                  {/* Date Header */}
                  <text fg="green">{group.date}</text>

                  {/* Sessions in this date group */}
                  {group.sessions.map((session) => {
                    const isSelected = session.index === selectedIndex;
                    const startTime = new Date(session.time.created);
                    const timeStr = startTime.toLocaleTimeString('en-US', {
                      hour: 'numeric',
                      minute: '2-digit',
                      hour12: true
                    });

                    return (
                      <box
                        id={session.id}
                        key={session.id}
                        onMouseDown={() => setSelectedIndex(session.index)}
                        backgroundColor="transparent"
                        border={isSelected ? ["left"] : undefined}
                        borderColor={isSelected ? "green" : undefined}
                        paddingLeft={2}
                        flexDirection="row"
                        justifyContent="space-between"
                        width="100%"
                      >
                        <text fg={isSelected ? "white" : "gray"}>
                          {isSelected ? "● " : "  "}{session.name}
                        </text>
                        <text fg="gray">{timeStr}</text>
                      </box>
                    );
                  })}
                </box>
              ))}
            </scrollbox>
          </box>
        )}

        {/* Actions Footer */}
        {visualOrderSessions.length > 0 && (
          <box flexDirection="row" gap={2}>
            <text fg="gray">
              <span fg="green">[Enter]</span> Open · <span fg="green">[R]</span> Report · <span fg="green">[Ctrl+D]</span> Delete
            </text>
          </box>
        )}

        {statusMessage && (
          <text fg="green">{statusMessage}</text>
        )}
      </box>
    </Dialog>
  );
}