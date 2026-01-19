/**
 * Message Renderer Component
 *
 * Unified message display component for both operator and chat views.
 * Delegates to UserMessage, SystemMessage, AssistantMessage, or ToolRenderer.
 */

import { memo, useMemo } from "react";
import { colors } from "../../theme";
import { markdownToStyledText } from "./markdown";
import { ToolRenderer } from "./tool-renderer";
import { isToolMessage } from "./type-guards";
import type { DisplayMessage } from "../agent-display";

interface MessageRendererProps {
  message: DisplayMessage;
  isStreaming?: boolean;
  verbose?: boolean;
  expandedLogs?: boolean;
  /** Variant affects user message styling */
  variant?: "operator" | "chat";
  /** Optional username for chat variant */
  username?: string;
}

/**
 * Unified message renderer - delegates to role-specific components.
 */
export const MessageRenderer = memo(function MessageRenderer({
  message,
  isStreaming = false,
  verbose = false,
  expandedLogs = false,
  variant = "operator",
  username = "user",
}: MessageRendererProps) {
  // Get string content
  const content =
    typeof message.content === "string"
      ? message.content
      : JSON.stringify(message.content);

  // Memoize markdown conversion for assistant messages
  const displayContent = useMemo(
    () => (message.role === "assistant" ? markdownToStyledText(content) : content),
    [content, message.role]
  );

  // Tool messages
  if (isToolMessage(message)) {
    return (
      <ToolRenderer
        message={message}
        verbose={verbose}
        expandedLogs={expandedLogs}
      />
    );
  }

  // User messages
  if (message.role === "user") {
    if (variant === "chat") {
      // Chat variant - cyan bar with username
      return (
        <box flexDirection="column" marginTop={1}>
          <box flexDirection="row">
            <text fg={colors.cyanAccent}>{"│ "}</text>
            <text fg={colors.creamText}>{content}</text>
          </box>
          <box marginLeft={2}>
            <text fg={colors.dimText}>{username}</text>
          </box>
        </box>
      );
    }
    // Operator variant - simple prompt style
    return (
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={colors.greenAccent}>{">"}</text>
        <text fg={colors.creamText}>{content}</text>
      </box>
    );
  }

  // System messages
  if (message.role === "system") {
    return (
      <box marginTop={1} marginLeft={2}>
        <text fg={colors.dimText}>{content}</text>
      </box>
    );
  }

  // Assistant messages
  if (variant === "chat") {
    // Chat variant - plain text, no bar
    return (
      <box flexDirection="column" marginTop={1}>
        <box flexDirection="column" marginLeft={0}>
          <text fg={colors.creamText} content={displayContent} />
          {isStreaming && !content.trim() && (
            <text fg={colors.dimText}>...</text>
          )}
        </box>
      </box>
    );
  }

  // Operator variant - green left bar (Claude Code style)
  return (
    <box flexDirection="column" marginTop={1}>
      <box flexDirection="row">
        <text fg={colors.greenAccent}>{"| "}</text>
        <box flexDirection="column" flexShrink={1}>
          <text fg={colors.creamText} content={displayContent} />
          {isStreaming && !content.trim() && (
            <text fg={colors.dimText}>...</text>
          )}
        </box>
      </box>
    </box>
  );
});

export default MessageRenderer;
