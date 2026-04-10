/**
 * Subagent Detail View
 *
 * Full-screen overlay showing a single subagent's conversation.
 * Reuses the MessageList component for rendering messages with
 * streaming, tool calls, and scrolling support.
 */

import { memo, useMemo } from "react";
import { useKeyboard } from "@opentui/react";

import { useTheme } from "../../theme";
import { useDimensions } from "../../context/dimensions";
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
// Header
// ---------------------------------------------------------------------------

interface SubagentDetailHeaderProps {
  session: SubagentSession;
  index: number;
  total: number;
}

const SubagentDetailHeader = memo(function SubagentDetailHeader({
  session,
  index,
  total,
}: SubagentDetailHeaderProps) {
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

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={0}
      flexShrink={0}
    >
      {/* Left: back hint + name */}
      <box flexDirection="row" gap={1}>
        <text fg={colors.textMuted} content={"\u2190"} />
        <text fg={colors.primary} content={session.name} />
      </box>

      {/* Right: position + status */}
      <box flexDirection="row" gap={1}>
        <text fg={colors.textMuted} content={`[${index}/${total}]`} />
        {statusNode}
      </box>
    </box>
  );
});

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
  const { width: termWidth } = useDimensions();

  const separatorLine = useMemo(
    () => "\u2500".repeat(Math.max(0, termWidth - 4)),
    [termWidth],
  );

  // Keyboard: Esc to go back, left/[ for prev, right/] for next.
  // Do NOT capture up/down — they propagate to the MessageList scrollbox.
  useKeyboard((key) => {
    if (key.name === "escape") {
      key.preventDefault?.();
      onBack();
      return;
    }

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
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <SubagentDetailHeader
        session={session}
        index={index}
        total={total}
      />

      {/* Separator */}
      <box paddingLeft={2} paddingRight={2} flexShrink={0}>
        <text fg={colors.borderSubtle} content={separatorLine} />
      </box>

      {/* Message list (body) */}
      <MessageList
        messages={session.messages}
        isRunning={session.status === "running"}
        variant="operator"
        focused={true}
      />

      {/* Footer */}
      <box paddingLeft={2} paddingBottom={1} flexShrink={0}>
        <text
          fg={colors.textMuted}
          content={"Esc back \u00b7 \u2190\u2192 prev/next \u00b7 scroll \u2191\u2193"}
        />
      </box>
    </box>
  );
});

export default SubagentDetailView;
