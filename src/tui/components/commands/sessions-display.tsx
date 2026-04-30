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
import DialogLayout from "../dialog-layout";
import { useDimensions } from "../../context/dimensions";

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
  const dimensions = useDimensions();

  const scroll = useRef<ScrollBoxRenderable>(null);

  const {
    groupedSessions,
    visualOrderSessions,
    loading,
    setSearchTerm,
    deleteSession: hookDeleteSession,
  } = useSessionsList();

  // Dialog inner box maxHeight is dimensions.height - 4.
  // DialogLayout chrome (padding, header, body marginTop, footer) uses ~8 rows.
  const availableListHeight = dimensions.height - 4 - 8;

  // Track whether the initial load had enough sessions to fill the dialog
  // (i.e., a scrollbar was needed). When true, pin the list height so
  // deleting sessions doesn't shrink the dialog.
  const initialOverflowRef = useRef<boolean | null>(null);
  if (!loading && initialOverflowRef.current === null) {
    // Each session row = 1 line, each date group header = 1 line,
    // gap between groups = 2, gap between sessions in group = 1.
    const groupCount = groupedSessions.length;
    const estimatedRows =
      visualOrderSessions.length + groupCount * 3 - (groupCount > 0 ? 2 : 0);
    initialOverflowRef.current = estimatedRows > availableListHeight;
  }

  // Only pin the height when the initial set overflowed the dialog
  const listHeight = initialOverflowRef.current
    ? availableListHeight
    : undefined;

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
      refocusPrompt();
      onClose();
      route.navigate({
        type: "operator",
        sessionId: currentSelection.id,
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
        type: "operator",
        sessionId: currentSelection.id,
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

  const footerActions =
    visualOrderSessions.length > 0
      ? [
          { key: "Enter", label: "open", variant: "primary" as const },
          { key: "O", label: "operator" },
          { key: "R", label: "report" },
          { key: "Ctrl+D", label: "delete", variant: "danger" as const },
        ]
      : [];

  return (
    <Dialog size="large" onClose={handleClose}>
      <DialogLayout title="Sessions" flushRight footerActions={footerActions}>
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
        {loading ? (
          <text fg={colors.textMuted}>Loading sessions...</text>
        ) : visualOrderSessions.length === 0 ? (
          <text fg={colors.textMuted}>No sessions found</text>
        ) : (
          <box
            flexDirection="column"
            gap={2}
            flexGrow={1}
            flexShrink={1}
            overflow="hidden"
            marginTop={1}
            height={listHeight}
          >
            <scrollbox
              ref={scroll}
              style={{
                rootOptions: {
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
                scrollbarOptions: {
                  visible: true,
                  trackOptions: {
                    foregroundColor: colors.primary,
                    backgroundColor: colors.backgroundElement,
                  },
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
                            {session.name ?? ""}
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
      </DialogLayout>
    </Dialog>
  );
}
