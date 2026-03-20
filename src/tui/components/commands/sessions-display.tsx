import { useState, useEffect, useRef, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { useFocus } from "../../context/focus";
import { sessions } from "../../../core/session";
import { openSessionReport, readSessionReport } from "../../utils/open-report";
import ReportViewerDialog from "../report-viewer-dialog";
import { REPORT_FILENAME_MD } from "../../../core/report";
import { Dialog } from "../../context/dialog";
import { ScrollBoxRenderable } from "@opentui/core";
import { scrollToIndex } from "../../utils/scroll";
import { useTheme } from "../../theme";
import { useSessionsList } from "../../hooks/use-sessions-list";
import { useToast } from "../../context/toast";
import { DialogControls } from "../shared/dialog-controls";

interface SessionsDisplayProps {
  onClose: () => void;
}

export default function SessionsDisplay({ onClose }: SessionsDisplayProps) {
  const { colors } = useTheme();
  const { refocusPrompt } = useFocus();
  const [selectedIndex, setSelectedIndex] = useState(0);
  const { toast } = useToast();
  const [showReportViewer, setShowReportViewer] = useState(false);
  const [reportContent, setReportContent] = useState<string | null>(null);
  const [reportSessionPath, setReportSessionPath] = useState<string | null>(
    null,
  );

  const route = useRoute();

  const scroll = useRef<ScrollBoxRenderable>(null);

  const {
    groupedSessions,
    visualOrderSessions,
    loading,
    setSearchTerm,
    deleteSession: hookDeleteSession,
  } = useSessionsList();

  const viewReport = useCallback(async (sessionId: string) => {
    const session = await sessions.get(sessionId);
    const content = readSessionReport(session.rootPath);
    if (!content) {
      toast("Report not found", "error");
      return;
    }
    setReportContent(content);
    setReportSessionPath(session.rootPath);
    setShowReportViewer(true);
  }, []);

  const openReportExternal = useCallback(async () => {
    if (!reportSessionPath) return;
    const err = await openSessionReport(reportSessionPath);
    if (err) {
      toast(err, "error");
    }
  }, [reportSessionPath]);

  // Clamp selectedIndex when list changes
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

  async function deleteSession(sessionId: string) {
    try {
      await hookDeleteSession(sessionId);
      toast("Session deleted");
      // selectedIndex clamping handled by the useEffect above after re-render
    } catch (error) {
      console.error("Error deleting session:", error);
      toast("Error deleting session", "error");
    }
  }

  useKeyboard(async (key) => {
    // Don't handle keys when report viewer is open
    if (showReportViewer) return;

    // Escape - Close sessions display
    if (key.name === "escape") {
      refocusPrompt();
      onClose();
      return;
    }

    // Enter - View existing session (respects original mode)
    if (key.name === "return" && visualOrderSessions.length > 0) {
      key.preventDefault();
      const currentSelection = visualOrderSessions[selectedIndex];
      if (!currentSelection) return;
      try {
        await sessions.get(currentSelection.id);
      } catch {
        toast("Session not found", "error");
        return;
      }
      const isOperator =
        currentSelection.config?.mode === "operator" ||
        (!currentSelection.config?.mode && currentSelection.hasOperatorState);
      refocusPrompt();
      onClose();
      route.navigate({
        type: "pentest",
        sessionId: currentSelection.id,
        openAsOperator: isOperator || undefined,
      });
      return;
    }

    // O - Open session in operator mode
    if (
      (key.name === "o" || key.name === "O") &&
      !key.ctrl &&
      !key.meta &&
      visualOrderSessions.length > 0
    ) {
      const currentSelection = visualOrderSessions[selectedIndex];
      if (!currentSelection) return;
      try {
        await sessions.get(currentSelection.id);
      } catch {
        toast("Session not found", "error");
        return;
      }
      refocusPrompt();
      onClose();
      route.navigate({
        type: "pentest",
        sessionId: currentSelection.id,
        openAsOperator: true,
      });
      return;
    }

    // Arrow Up - Previous session
    if (key.name === "up" && visualOrderSessions.length > 0) {
      const newIndex =
        selectedIndex > 0 ? selectedIndex - 1 : visualOrderSessions.length - 1;
      setSelectedIndex(newIndex);
      scrollToIndex(scroll.current, newIndex, visualOrderSessions, (s) => s.id);
      return;
    }

    // Arrow Down - Next session
    if (key.name === "down" && visualOrderSessions.length > 0) {
      const newIndex =
        selectedIndex < visualOrderSessions.length - 1 ? selectedIndex + 1 : 0;
      setSelectedIndex(newIndex);
      scrollToIndex(scroll.current, newIndex, visualOrderSessions, (s) => s.id);
      return;
    }

    // R - View report in dialog
    if (key.name === "r" && visualOrderSessions.length > 0) {
      const currentSelection = visualOrderSessions[selectedIndex];
      if (!currentSelection) return;
      if (!currentSelection.hasReport) {
        toast("No report available", "warn");
        return;
      }
      viewReport(currentSelection.id);
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

  if (loading) return null;

  if (showReportViewer && reportContent && reportSessionPath) {
    return (
      <ReportViewerDialog
        content={reportContent}
        reportPath={`${reportSessionPath}/${REPORT_FILENAME_MD}`}
        onClose={() => setShowReportViewer(false)}
        onOpenExternal={openReportExternal}
      />
    );
  }

  return (
    <Dialog size="large" onClose={handleClose}>
      <box flexDirection="column" padding={2} gap={2} width="100%">
        {/* Header */}
        <box flexDirection="row" width="100%">
          <text fg={colors.text}>Sessions</text>
        </box>

        {/* Search Input */}
        <box
          width="100%"
          border={["left"]}
          borderColor={colors.primary}
          backgroundColor="transparent"
        >
          <input
            paddingLeft={1}
            backgroundColor="transparent"
            placeholder="Search sessions..."
            onInput={setSearchTerm}
            focused
            cursorColor={colors.textMuted}
            textColor={colors.text}
            focusedTextColor={colors.text}
          />
        </box>

        {/* Sessions List */}
        {visualOrderSessions.length === 0 ? (
          <text fg={colors.textMuted}>No sessions found</text>
        ) : (
          <box
            flexDirection="column"
            gap={2}
            flexGrow={1}
            maxHeight={10}
            overflow="hidden"
          >
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
                  <text fg={colors.primary}>{group.date}</text>

                  {/* Sessions in this date group */}
                  {group.sessions.map((session) => {
                    const isSelected = session.index === selectedIndex;
                    const startTime = new Date(session.time.created);
                    const timeStr = startTime.toLocaleTimeString("en-US", {
                      hour: "numeric",
                      minute: "2-digit",
                      hour12: true,
                    });
                    const mode = session.config?.mode || "auto";
                    const modeBadge =
                      mode === "operator" ? "[operator]" : "[auto]";
                    const statusBadge = session.hasReport ? "✓" : "…";
                    const findingsText =
                      session.findingsCount > 0
                        ? `${session.findingsCount} finding${session.findingsCount > 1 ? "s" : ""}`
                        : "";

                    return (
                      <box
                        id={session.id}
                        key={session.id}
                        onMouseDown={() => setSelectedIndex(session.index)}
                        backgroundColor="transparent"
                        border={isSelected ? ["left"] : undefined}
                        borderColor={isSelected ? colors.primary : undefined}
                        paddingLeft={2}
                        flexDirection="row"
                        justifyContent="space-between"
                        width="100%"
                      >
                        <box flexDirection="row" gap={1}>
                          <text
                            fg={isSelected ? colors.primary : colors.textMuted}
                          >
                            {isSelected ? "●" : " "}
                          </text>
                          <text
                            fg={isSelected ? colors.text : colors.textMuted}
                          >
                            {session.name}
                          </text>
                          <text
                            fg={
                              session.hasReport
                                ? colors.primary
                                : colors.textMuted
                            }
                          >
                            {statusBadge}
                          </text>
                          <text
                            fg={
                              mode === "operator"
                                ? colors.primary
                                : colors.textMuted
                            }
                          >
                            {modeBadge}
                          </text>
                          {findingsText ? (
                            <text fg={colors.textMuted}>{findingsText}</text>
                          ) : null}
                        </box>
                        <text fg={colors.textMuted}>{timeStr}</text>
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
          <DialogControls
            controls={[
              { key: "Enter", label: "Open", variant: "primary" },
              { key: "↑/↓", label: "Navigate" },
              { key: "O", label: "Operator" },
              { key: "R", label: "Report" },
              { key: "Ctrl+D", label: "Delete", variant: "danger" },
              { key: "Esc", label: "Close" },
            ]}
          />
        )}
      </box>
    </Dialog>
  );
}
