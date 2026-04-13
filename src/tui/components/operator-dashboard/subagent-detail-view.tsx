/**
 * Subagent Detail View Dialog
 *
 * Dialog showing a single subagent's conversation.
 * Reuses the MessageList component for rendering messages with
 * streaming, tool calls, and scrolling support.
 */

import React, { memo } from "react";
import { useKeyboard } from "@opentui/react";

import { useTheme } from "../../theme";
import { MessageList } from "../chat/message-list";
import { AsciiSpinner } from "../shared/ascii-spinner";
import type { SubagentSession } from "./subagent-state";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SubagentDetailViewProps {
  session: SubagentSession;
  /** 1-indexed position in the sessions list */
  index: number;
  /** Total number of sessions */
  total: number;
  onPrev: () => void;
  onNext: () => void;
  onBack: () => void;
}

// ---------------------------------------------------------------------------
// SubagentDetailView
// ---------------------------------------------------------------------------

export const SubagentDetailView = memo(function SubagentDetailView({
  session,
  index,
  total,
  onPrev,
  onNext,
  onBack,
}: SubagentDetailViewProps) {
  const { colors } = useTheme();

  let statusNode: React.ReactNode;
  switch (session.status) {
    case "running":
      statusNode = <AsciiSpinner label="running" fg={colors.warning} />;
      break;
    case "completed":
      statusNode = <text fg={colors.success} content={"\u2713 completed"} />;
      break;
    case "failed":
      statusNode = <text fg={colors.error} content={"\u2717 failed"} />;
      break;
  }

  // Left/right to cycle between subagents.
  // Escape is handled by SubagentDialog (parent).
  // Up/down are NOT captured — they propagate to the MessageList scrollbox.
  useKeyboard((key) => {
    if (key.name === "left" || key.raw === "[") {
      key.preventDefault?.();
      onPrev();
      return;
    }

    if (key.name === "right" || key.raw === "]") {
      key.preventDefault?.();
      onNext();
      return;
    }
  });

  return (
    <box flexDirection="column" width="100%" flexGrow={1}>
      {/* Sub-header: name + position + status */}
      <box flexDirection="row" justifyContent="space-between" flexShrink={0}>
        {/* Left: name */}
        <text fg={colors.primary} content={session.name} />

        {/* Right: position + status */}
        <box flexDirection="row" gap={1}>
          <text fg={colors.textMuted} content={`[${index}/${total}]`} />
          {statusNode}
        </box>
      </box>

      {/* Message list (body) */}
      <MessageList
        messages={session.messages}
        isRunning={session.status === "running"}
        variant="subagent"
        focused={true}
      />
    </box>
  );
});

export default SubagentDetailView;
