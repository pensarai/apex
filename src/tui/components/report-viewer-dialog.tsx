import { useRef, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import { useTheme } from "../theme";
import { Dialog } from "../context/dialog";
import DialogLayout from "./dialog-layout";
import { useMarkdownSyntaxStyle, useMarkdownRenderNode } from "./shared";

interface ReportViewerDialogProps {
  content: string;
  reportPath: string;
  onClose: () => void;
  onOpenExternal?: () => void;
}

export default function ReportViewerDialog({
  content,
  reportPath,
  onClose,
  onOpenExternal,
}: ReportViewerDialogProps) {
  const { colors } = useTheme();
  const scrollRef = useRef<ScrollBoxRenderable>(null);
  const syntaxStyle = useMarkdownSyntaxStyle();
  const renderNode = useMarkdownRenderNode();

  const lineCount = useMemo(() => content.split("\n").length, [content]);

  useKeyboard((evt) => {
    if (evt.name === "escape") {
      evt.preventDefault();
      onClose();
      return;
    }
    if (
      (evt.name === "e" || evt.name === "E") &&
      !evt.ctrl &&
      !evt.meta &&
      onOpenExternal
    ) {
      evt.preventDefault();
      onOpenExternal();
      return;
    }
  });

  const title = (
    <text>
      <span fg={colors.primary}>Pentest Report</span>
      <span fg={colors.textMuted}> {reportPath}</span>
      <span fg={colors.textMuted}> ({lineCount} lines)</span>
    </text>
  );

  const footerActions = onOpenExternal
    ? [{ key: "E", label: "open in editor", variant: "primary" as const }]
    : [];

  return (
    <Dialog size="xlarge" onClose={onClose}>
      <DialogLayout title={title} flushRight footerActions={footerActions}>
        {/* Report Content */}
        <scrollbox
          ref={scrollRef}
          style={{
            rootOptions: {
              flexGrow: 1,
              width: "100%",
              overflow: "hidden",
            },
            contentOptions: {
              paddingLeft: 2,
              paddingRight: 2,
              paddingTop: 1,
              paddingBottom: 1,
              flexDirection: "column",
            },
            scrollbarOptions: {
              trackOptions: {
                foregroundColor: colors.textMuted,
                backgroundColor: colors.backgroundElement,
              },
            },
          }}
          stickyScroll={false}
          focused={true}
        >
          <markdown
            content={content}
            syntaxStyle={syntaxStyle}
            conceal={true}
            renderNode={renderNode}
          />
        </scrollbox>
      </DialogLayout>
    </Dialog>
  );
}
