/**
 * Message List Component
 *
 * Scrollable container for chat messages.
 * Auto-scrolls to bottom as new messages arrive.
 */

import type { DisplayMessage } from "../../agent-display";
import { colors } from "../../../theme";
import { MessageRenderer, getStableMessageKey } from "../../shared";

interface MessageListProps {
  messages: DisplayMessage[];
  streamingMessageIndex?: number;
  isRunning?: boolean;
  username?: string;
  emptyMessage?: string;
  focused?: boolean;
}

export function MessageList({
  messages,
  streamingMessageIndex = -1,
  isRunning = false,
  username = "user",
  emptyMessage,
  focused = true,
}: MessageListProps) {
  const hasMessages = messages.length > 0;
  const lastMessage = messages[messages.length - 1];
  const isLastAssistant = lastMessage?.role === "assistant";

  return (
    <scrollbox
      style={{
        rootOptions: { flexGrow: 1, width: "100%" },
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
      {/* Empty state */}
      {!hasMessages && emptyMessage && (
        <box flexDirection="column" gap={1} marginTop={2}>
          <text fg={colors.greenAccent}>Chat Ready</text>
          <text fg={colors.dimText}>{emptyMessage}</text>
        </box>
      )}

      {/* Welcome tips when empty */}
      {!hasMessages && !emptyMessage && (
        <box flexDirection="column" gap={1} marginTop={2}>
          <text fg={colors.greenAccent}>Ready</text>
          <text fg={colors.dimText}>
            Type a directive to begin exploring.
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
          key={getStableMessageKey(msg, "chat")}
          message={msg}
          isStreaming={isRunning && idx === streamingMessageIndex}
          variant="chat"
          username={username}
        />
      ))}

      {/* Thinking indicator */}
      {isRunning && !isLastAssistant && messages.length > 0 && (
        <box marginTop={1} marginLeft={2}>
          <text fg={colors.dimText} content="Thinking..." />
        </box>
      )}
    </scrollbox>
  );
}

export default MessageList;
