/**
 * Subagent Detail View Dialog
 *
 * Dialog showing a single subagent's conversation.
 * Reuses the MessageList component for rendering messages with
 * streaming, tool calls, and scrolling support.
 */

import { useKeyboard } from "@opentui/react";
import { memo } from "react";

import { MessageList } from "../chat/message-list";
import type { SubagentSession } from "./subagent-state";

export interface SubagentDetailViewProps {
  session: SubagentSession;
  onPrev: () => void;
  onNext: () => void;
}

export const SubagentDetailView = memo(function SubagentDetailView({
  session,
  onPrev,
  onNext,
}: SubagentDetailViewProps) {
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
    <MessageList
      messages={session.messages}
      isRunning={session.status === "running"}
      variant="subagent"
      focused={true}
    />
  );
});

export default SubagentDetailView;
