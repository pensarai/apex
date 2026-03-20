import { useRef, useMemo, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { useDimensions } from "../context/dimensions";
import {
  Renderable,
  ScrollBoxRenderable,
  SyntaxStyle,
  type CodeRenderable,
} from "@opentui/core";
import type { Token } from "marked";
import { useTheme } from "../theme";
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
  const scrollRef = useRef<ScrollBoxRenderable>(null);

  const syntaxStyle = useMemo(
    () =>
      SyntaxStyle.fromStyles({
        default: { fg: colors.text },
        "markup.heading": { fg: colors.markdownHeading, bold: true },
        "markup.strong": { fg: colors.markdownStrong, bold: true },
        "markup.italic": { fg: colors.markdownEmph, italic: true },
        "markup.raw": { fg: colors.markdownCode },
        "markup.raw.block": { fg: colors.markdownCode },
        "markup.link": { fg: colors.markdownLink },
        "markup.link.url": { fg: colors.markdownLink, dim: true },
        "markup.link.label": { fg: colors.markdownLink, underline: true },
        "markup.strikethrough": { fg: colors.textMuted, dim: true },
        "markup.list": { fg: colors.primary },
        "markup.quote": { fg: colors.textMuted, italic: true },
        "punctuation.special": { fg: colors.border },
      }),
    [colors],
  );

  // Override code block rendering to set theme-aware fg color.
  // Without this, CodeRenderable defaults to white text (opentui default),
  // which is invisible on light backgrounds.
  const renderNode = useCallback(
    (
      token: Token,
      ctx: { defaultRender: () => Renderable | null },
    ): Renderable | undefined | null => {
      if (token.type === "code") {
        const renderable = ctx.defaultRender();
        if (renderable) {
          (renderable as CodeRenderable).fg = colors.markdownCode;
        }
        return renderable;
      }
      return undefined;
    },
    [colors.markdownCode],
  );

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
        {/* Header */}
        <box
          width="100%"
          padding={1}
          flexDirection="row"
          justifyContent="space-between"
        >
          <text fg={colors.primary}>Pentest Report</text>
          <text fg={colors.textMuted}>{reportPath}</text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

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
                foregroundColor: colors.primary,
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

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Footer */}
        <box
          width="100%"
          padding={1}
          flexDirection="row"
          justifyContent="space-between"
        >
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
              { key: "↑/↓", label: "Scroll" },
              { key: "Esc", label: "Close" },
            ]}
          />
          <text fg={colors.textMuted}>{lineCount} lines</text>
        </box>
      </box>
    </box>
  );
}
