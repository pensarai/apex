/**
 * Chat View Component
 *
 * Scrollable message display for Operator dashboard.
 * Clean, Claude Code-like layout.
 */

import type { DisplayMessage } from "../agent-display";
import type { PendingApproval } from "../../../core/operator";
import { colors } from "../../theme";
import {
  MessageRenderer,
  InlineApprovalPrompt,
  getStableMessageKey,
} from "../shared";

interface ChatViewProps {
  messages: DisplayMessage[];
  status: string;
  streamingMessageIndex: number;
  pendingApprovals: PendingApproval[];
  hasPendingTool: boolean;
  lastApprovedAction: string | null;
  verboseMode: boolean;
  expandedLogs: boolean;
}

export function ChatView({
  messages,
  status,
  streamingMessageIndex,
  pendingApprovals,
  hasPendingTool,
  lastApprovedAction,
  verboseMode,
  expandedLogs,
}: ChatViewProps) {
  const isRunning = status === "running";
  const hasPendingApproval = pendingApprovals.length > 0;
  const lastMessage = messages[messages.length - 1];
  const lastMessageIsAssistant = lastMessage?.role === "assistant";

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
      focused={true}
    >
      {/* Welcome message if empty */}
      {messages.length === 0 && status === "idle" && (
        <box flexDirection="column" gap={1} marginTop={2}>
          <text fg={colors.greenAccent}>Operator Mode Active</text>
          <text fg={colors.dimText}>
            Type a directive to begin (e.g., "Explore the attack surface").
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

      {/* Messages */}
      {messages.map((msg, idx) => (
        <MessageRenderer
          key={getStableMessageKey(msg, "operator")}
          message={msg}
          isStreaming={isRunning && idx === streamingMessageIndex}
          verbose={verboseMode}
          expandedLogs={expandedLogs}
          variant="operator"
        />
      ))}

      {/* Thinking indicator - show when agent is processing but not when there's a pending approval */}
      {isRunning && !hasPendingApproval && !lastMessageIsAssistant && (
        <box marginTop={1} marginLeft={2}>
          <text
            fg={colors.dimText}
            content={
              hasPendingTool
                ? lastApprovedAction
                  ? `Executing: ${lastApprovedAction}`
                  : "Executing..."
                : "Thinking..."
            }
          />
        </box>
      )}

      {/* Approval prompt - shown inline at the bottom of the chat */}
      {hasPendingApproval && (
        <InlineApprovalPrompt approval={pendingApprovals[0]} />
      )}
    </scrollbox>
  );
}

export default ChatView;
