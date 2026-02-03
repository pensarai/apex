/**
 * Session Message List Component
 *
 * Scrollable container for chat messages with auto-scroll.
 * Unified for both chat and operator modes.
 */

import { colors } from "../../theme";
import { MessageRenderer, getStableMessageKey, isToolMessage } from "../shared";
import type { DisplayMessage } from "../agent-display";
import type { PendingApproval } from "../../../core/operator";
import { InlineApprovalPrompt } from "./approval-inline";
import { LoadingIndicator, type LoadingState } from "./loading-indicator";

/**
 * Determine loading state based on message context
 */
function getLoadingState(
  messages: DisplayMessage[],
  hasPendingTool: boolean,
  isLastAssistant: boolean
): LoadingState {
  if (hasPendingTool) {
    return "executing";
  }
  if (isLastAssistant) {
    return "streaming";
  }
  return "thinking";
}

/**
 * Get the name of any pending tool from recent messages
 */
function getPendingToolName(messages: DisplayMessage[]): string | null {
  const recentMessages = messages.slice(-5);
  for (const msg of recentMessages.reverse()) {
    if (isToolMessage(msg) && msg.status === "pending") {
      return msg.toolName || null;
    }
  }
  return null;
}

export interface MessageListProps {
  /** Messages to display */
  messages: DisplayMessage[];
  /** Index of currently streaming message */
  streamingMessageIndex?: number;
  /** Is agent currently running */
  isRunning?: boolean;
  /** Display variant */
  variant?: "chat" | "operator";
  /** Username for chat variant */
  username?: string;
  /** Empty state message */
  emptyMessage?: string;
  /** Whether scroll is focused */
  focused?: boolean;
  /** Verbose mode for tool display */
  verbose?: boolean;
  /** Expanded logs for tool display */
  expandedLogs?: boolean;
  /** Pending approvals to show inline */
  pendingApprovals?: PendingApproval[];
  /** Whether there's a pending tool execution */
  hasPendingTool?: boolean;
  /** Last approved action description */
  lastApprovedAction?: string | null;
}

/**
 * Message list with auto-scroll and empty state handling
 */
export function MessageList({
  messages,
  streamingMessageIndex = -1,
  isRunning = false,
  variant = "operator",
  username = "user",
  emptyMessage,
  focused = true,
  verbose = false,
  expandedLogs = false,
  pendingApprovals = [],
  hasPendingTool = false,
  lastApprovedAction = null,
}: MessageListProps) {
  const hasMessages = messages.length > 0;
  const lastMessage = messages[messages.length - 1];
  const isLastAssistant = lastMessage?.role === "assistant";
  const hasPendingApproval = pendingApprovals.length > 0;

  return (
    <scrollbox
      style={{
        rootOptions: { flexGrow: 1, flexShrink: 1, width: "100%", overflow: "hidden" },
        contentOptions: {
          paddingLeft: 2,
          paddingRight: 2,
          paddingBottom: 2,
          flexDirection: "column",
        },
      }}
      stickyScroll={true}
      stickyStart="bottom"
      focused={focused}
    >
      {/* Empty state - Operator mode */}
      {!hasMessages && variant === "operator" && (
        <box flexDirection="column" gap={1} marginTop={2}>
          <text fg={colors.greenAccent}>Operator Mode Active</text>
          <text fg={colors.dimText}>
            {emptyMessage || 'Type a directive to begin (e.g., "Explore the attack surface").'}
          </text>
          <box flexDirection="column" gap={0} marginTop={1}>
            <text fg={colors.creamText}>Tips:</text>
            <box flexDirection="row">
              <text fg={colors.greenAccent}>/auth</text>
              <text fg={colors.dimText}> - Configure authentication</text>
            </box>
            <box flexDirection="row">
              <text fg={colors.greenAccent}>Shift+Tab</text>
              <text fg={colors.dimText}> - Cycle modes (plan/manual/auto)</text>
            </box>
            <box flexDirection="row">
              <text fg={colors.greenAccent}>Ctrl+S</text>
              <text fg={colors.dimText}> - Change stage</text>
            </box>
          </box>
        </box>
      )}

      {/* Empty state - Chat mode */}
      {!hasMessages && variant === "chat" && (
        <box flexDirection="column" gap={1} marginTop={2}>
          <text fg={colors.greenAccent}>Ready</text>
          <text fg={colors.dimText}>
            {emptyMessage || "Type a directive to begin exploring."}
          </text>
          <box flexDirection="column" gap={0} marginTop={1}>
            <text fg={colors.creamText}>Tips:</text>
            <box flexDirection="row">
              <text fg={colors.greenAccent}>/config</text>
              <text fg={colors.dimText}> - Configure target and settings</text>
            </box>
            <box flexDirection="row">
              <text fg={colors.greenAccent}>Ctrl+B</text>
              <text fg={colors.dimText}> - Toggle sidebar</text>
            </box>
            <box flexDirection="row">
              <text fg={colors.greenAccent}>Ctrl+C</text>
              <text fg={colors.dimText}> - Stop current action</text>
            </box>
          </box>
        </box>
      )}

      {/* Messages */}
      {messages.map((msg, idx) => (
        <MessageRenderer
          key={getStableMessageKey(msg, variant)}
          message={msg}
          isStreaming={isRunning && idx === streamingMessageIndex}
          verbose={verbose}
          expandedLogs={expandedLogs}
          variant={variant}
          username={username}
        />
      ))}

      {/* Loading indicator - show when running but not when there's a pending approval */}
      {isRunning && !hasPendingApproval && hasMessages && (
        <LoadingIndicator
          state={getLoadingState(messages, hasPendingTool, isLastAssistant)}
          action={lastApprovedAction}
          toolName={getPendingToolName(messages)}
        />
      )}

      {/* Approval prompt - shown inline at the bottom of the chat */}
      {hasPendingApproval && (
        <InlineApprovalPrompt approval={pendingApprovals[0]} />
      )}
    </scrollbox>
  );
}

export default MessageList;
