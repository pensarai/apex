/**
 * Unified Approval Prompt Components
 *
 * Single implementation for approval UI used in both operator and chat views.
 */

import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme } from "../../theme";
import { getToolSummary } from "./tool-registry";
import { IntentBadge } from "./intent-badge";
import type { PendingApproval } from "../../../core/operator";
import { getPasteText } from "../../utils/paste";
import { useDialog } from "../../context/dialog";

interface InlineApprovalPromptProps {
  approval: PendingApproval;
}

/**
 * Inline approval prompt - shows pending tool call.
 * Displayed in the chat flow.
 */
export function InlineApprovalPrompt({ approval }: InlineApprovalPromptProps) {
  const { colors } = useTheme();

  const description = approval.args?.toolCallDescription as string | undefined;
  const summary = getToolSummary(approval.toolName, approval.args || {});

  return (
    <box flexDirection="column" marginTop={2}>
      {description && (
        <box flexDirection="row" marginBottom={1}>
          <text fg={colors.primary} content="| " />
          <text fg={colors.text} content={description} />
        </box>
      )}

      <box flexDirection="row" gap={1} marginLeft={2}>
        <text fg={colors.warning} content="?" />
        <IntentBadge approval={approval} />
        <text fg={colors.info} content={summary} />
      </box>
    </box>
  );
}

interface ApprovalInputAreaProps {
  approval: PendingApproval;
  onApprove: () => void;
  onAutoApprove: () => void;
  onRedirect: (message: string) => void;
  redirectInput: string;
  setRedirectInput: (value: string) => void;
  lastDeclineNote?: string | null;
}

/**
 * Approval input area - shows at the bottom of the screen.
 * Provides Yes/Auto/Redirect options.
 */
export function ApprovalInputArea({
  approval,
  onApprove,
  onAutoApprove,
  onRedirect,
  redirectInput,
  setRedirectInput,
  lastDeclineNote,
}: ApprovalInputAreaProps) {
  const { colors } = useTheme();
  const { setExternalDialogOpen } = useDialog();
  const [focusedElement, setFocusedElement] = useState(0);

  // Signal to dashboard that redirect input is focused so it skips Y/A shortcuts
  useEffect(() => {
    setExternalDialogOpen(focusedElement === 2);
    return () => setExternalDialogOpen(false);
  }, [focusedElement, setExternalDialogOpen]);

  useKeyboard((key) => {
    if (key.name === "up") {
      setFocusedElement((prev) => Math.max(0, prev - 1));
      return;
    }
    if (key.name === "down" || (key.name === "tab" && !key.shift)) {
      setFocusedElement((prev) => Math.min(2, prev + 1));
      return;
    }
    if (key.name === "tab" && key.shift) {
      setFocusedElement((prev) => Math.max(0, prev - 1));
      return;
    }

    if (key.name === "return") {
      if (focusedElement === 0) {
        onApprove();
      } else if (focusedElement === 1) {
        onAutoApprove();
      } else if (focusedElement === 2 && redirectInput.trim()) {
        onRedirect(redirectInput);
      }
      return;
    }

    // When redirect input is focused, Y/A keys go to the input (no preventDefault).
    // Dashboard handler is blocked via externalDialogOpen state.
    if (focusedElement === 2) {
      if (
        key.name === "y" ||
        key.raw === "Y" ||
        key.name === "a" ||
        key.raw === "A"
      ) {
        return;
      }
    }
  });

  return (
    <box
      flexDirection="column"
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
    >
      <box flexDirection="row" gap={1} marginBottom={1}>
        <IntentBadge approval={approval} />
        <text
          fg={colors.textMuted}
          content={approval.classification.reasoning}
        />
      </box>

      {/* Yes option */}
      <box flexDirection="row" gap={1}>
        <text
          fg={focusedElement === 0 ? colors.primary : colors.textMuted}
          content={focusedElement === 0 ? ">" : " "}
        />
        <text
          fg={focusedElement === 0 ? colors.text : colors.textMuted}
          content="Yes - approve this action"
        />
      </box>

      {/* Auto option */}
      <box flexDirection="row" gap={1}>
        <text
          fg={focusedElement === 1 ? colors.warning : colors.textMuted}
          content={focusedElement === 1 ? ">" : " "}
        />
        <text
          fg={focusedElement === 1 ? colors.text : colors.textMuted}
          content="Approve this + auto-approve safe from now"
        />
      </box>

      {/* Redirect input */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text
          fg={focusedElement === 2 ? colors.primary : colors.textMuted}
          content={focusedElement === 2 ? ">" : " "}
        />
        <text fg={colors.primary} content=">" />
        <input
          width="100%"
          value={redirectInput}
          onInput={setRedirectInput}
          onPaste={(event) => {
            const cleaned = getPasteText(event).replace(/\r?\n/g, " ");
            setRedirectInput(cleaned);
          }}
          focused={focusedElement === 2}
          placeholder="Tell the agent something else..."
          textColor={colors.text}
          backgroundColor="transparent"
          cursorColor={colors.textMuted}
        />
      </box>

      {lastDeclineNote && (
        <box marginTop={1} marginLeft={2}>
          <text
            fg={colors.textMuted}
            content={`Declined: ${lastDeclineNote}`}
          />
        </box>
      )}

      {/* Shortcuts hint */}
      <box flexDirection="row" gap={2} marginTop={1}>
        <text
          fg={colors.textMuted}
          content="Y approve | A auto-approve safe | Enter select"
        />
      </box>
    </box>
  );
}

export default ApprovalInputArea;
