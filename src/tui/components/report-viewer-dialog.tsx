import { useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { useDimensions } from "../context/dimensions";
import { useTheme } from "../theme";
import { MarkdownViewer } from "./shared/markdown-viewer";
import { DialogControls } from "./shared/dialog-controls";

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
  const dimensions = useDimensions();
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

  const panelWidth = Math.min(120, dimensions.width - 4);
  const panelHeight = dimensions.height - 4;

  return (
    <box
      width={dimensions.width}
      height={dimensions.height}
      alignItems="center"
      justifyContent="center"
      position="absolute"
      left={0}
      top={0}
      backgroundColor={colors.backgroundOverlay}
    >
      <box
        width={panelWidth}
        height={panelHeight}
        backgroundColor={colors.backgroundPanel}
        borderColor={colors.primary}
        borderStyle="single"
        flexDirection="column"
      >
        <MarkdownViewer
          content={content}
          width={panelWidth}
          headerLeft={<text fg={colors.primary}>Pentest Report</text>}
          headerRight={<text fg={colors.textMuted}>{reportPath}</text>}
          footerLeft={
            <DialogControls
              controls={[
                ...(onOpenExternal
                  ? [
                      {
                        key: "E",
                        label: "Open in Editor",
                        variant: "primary" as const,
                      },
                    ]
                  : []),
              ]}
            />
          }
          footerRight={<text fg={colors.textMuted}>{lineCount} lines</text>}
        />
      </box>
    </box>
  );
}
