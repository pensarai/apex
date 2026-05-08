/**
 * Shared markdown content viewer with themed syntax highlighting.
 *
 * Content-only component — does not manage its own overlay or positioning.
 * Callers wrap it in <Dialog>, a custom overlay, or any other container.
 */

import {
  type CodeRenderable,
  type Renderable,
  type ScrollBoxRenderable,
  SyntaxStyle,
} from "@opentui/core";
import type { Token } from "marked";
import { type ReactNode, useCallback, useMemo, useRef } from "react";
import { useTheme } from "../../theme";

interface MarkdownViewerProps {
  /** Markdown content to render */
  content: string;
  /** Show loading placeholder instead of content */
  loading?: boolean;
  /** Available width — used for separator line calculation */
  width: number;
  /** Header left side (title, name, etc.) */
  headerLeft: ReactNode;
  /** Header right side (path, token count, etc.) */
  headerRight?: ReactNode;
  /** Optional section between header and scrollable content (e.g. metadata) */
  beforeContent?: ReactNode;
  /** Footer left side (keyboard hints) */
  footerLeft: ReactNode;
  /** Footer right side (line count, etc.) */
  footerRight?: ReactNode;
}

/**
 * Shared markdown SyntaxStyle derived from theme colors.
 */
export function useMarkdownSyntaxStyle() {
  const { colors } = useTheme();
  return useMemo(
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
}

/**
 * Shared renderNode override for code blocks — sets theme-aware fg color.
 * Without this, CodeRenderable defaults to white text (opentui default),
 * which is invisible on light backgrounds.
 */
export function useMarkdownRenderNode() {
  const { colors } = useTheme();
  return useCallback(
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
}

export function MarkdownViewer({
  content,
  loading = false,
  width,
  headerLeft,
  headerRight,
  beforeContent,
  footerLeft,
  footerRight,
}: MarkdownViewerProps) {
  const { colors } = useTheme();
  const scrollRef = useRef<ScrollBoxRenderable>(null);
  const syntaxStyle = useMarkdownSyntaxStyle();
  const renderNode = useMarkdownRenderNode();
  const separatorLine = "─".repeat(Math.max(0, width - 2));

  return (
    <box flexDirection="column" width="100%">
      {/* Header */}
      <box
        width="100%"
        padding={1}
        flexDirection="row"
        justifyContent="space-between"
      >
        {headerLeft}
        {headerRight}
      </box>

      {/* Separator */}
      <box width="100%" height={1}>
        <text fg={colors.border}>{separatorLine}</text>
      </box>

      {/* Optional metadata section */}
      {beforeContent}

      {/* Separator after metadata (only when metadata is present) */}
      {beforeContent && (
        <box width="100%" height={1} marginTop={1}>
          <text fg={colors.border}>{separatorLine}</text>
        </box>
      )}

      {/* Scrollable markdown content */}
      <scrollbox
        ref={scrollRef}
        style={{
          rootOptions: {
            flexGrow: 1,
            flexShrink: 1,
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
        {loading ? (
          <text fg={colors.textMuted}>Loading...</text>
        ) : (
          <markdown
            content={content}
            syntaxStyle={syntaxStyle}
            conceal={true}
            renderNode={renderNode}
          />
        )}
      </scrollbox>

      {/* Separator */}
      <box width="100%" height={1}>
        <text fg={colors.border}>{separatorLine}</text>
      </box>

      {/* Footer */}
      <box
        width="100%"
        padding={1}
        flexDirection="row"
        justifyContent="space-between"
      >
        {footerLeft}
        {footerRight}
      </box>
    </box>
  );
}
