/**
 * Unified Approval Prompt Components
 *
 * Single implementation for approval UI used in both operator and chat views.
 * Replaces 2 duplicate implementations.
 */

import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { colors, getTierColor } from "../../theme";
import { getToolSummary } from "./tool-registry";
import type { PendingApproval, PermissionTier } from "../../../core/operator";

interface InlineApprovalPromptProps {
  approval: PendingApproval;
}

/**
 * Inline approval prompt - shows pending tool call with tier info.
 * Displayed in the chat flow.
 */
export function InlineApprovalPrompt({ approval }: InlineApprovalPromptProps) {
  const tierColor = getTierColor(approval.tier);

  // Get the description if provided
  const description = approval.args?.toolCallDescription as string | undefined;

  // Get tool summary from registry
  const summary = getToolSummary(approval.toolName, approval.args || {});

  return (
    <box flexDirection="column" marginTop={2}>
      {/* Description from agent if available */}
      {description && (
        <box flexDirection="row" marginBottom={1}>
          <text fg={colors.greenAccent} content="| " />
          <text fg={colors.creamText} content={description} />
        </box>
      )}

      {/* Approval line */}
      <box flexDirection="row" gap={1} marginLeft={2}>
        <text fg={colors.yellowText} content="?" />
        <text fg={tierColor} content={`[T${approval.tier}]`} />
        <text fg={colors.toolColor} content={summary} />
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
  const [focusedElement, setFocusedElement] = useState(0); // 0=Yes, 1=Auto, 2=Input

  useKeyboard((key) => {
    // Navigation
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

    // Enter to select
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
  });

  return (
    <box
      flexDirection="column"
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
    >
      {/* Yes option */}
      <box flexDirection="row" gap={1}>
        <text
          fg={focusedElement === 0 ? colors.greenAccent : colors.dimText}
          content={focusedElement === 0 ? ">" : " "}
        />
        <text
          fg={focusedElement === 0 ? colors.creamText : colors.dimText}
          content="Yes - approve this action"
        />
      </box>

      {/* Auto option */}
      <box flexDirection="row" gap={1}>
        <text
          fg={focusedElement === 1 ? colors.yellowText : colors.dimText}
          content={focusedElement === 1 ? ">" : " "}
        />
        <text
          fg={focusedElement === 1 ? colors.creamText : colors.dimText}
          content={`Auto - auto-approve T1-T${approval.tier} from now`}
        />
      </box>

      {/* Redirect input */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text
          fg={focusedElement === 2 ? colors.greenAccent : colors.dimText}
          content={focusedElement === 2 ? ">" : " "}
        />
        <text fg={colors.greenAccent} content=">" />
        <input
          width="100%"
          value={redirectInput}
          onInput={setRedirectInput}
          onPaste={(event) => {
            const cleaned = String(event.text).replace(/\r?\n/g, " ");
            setRedirectInput(cleaned);
          }}
          focused={focusedElement === 2}
          placeholder="Tell the agent something else..."
          textColor="white"
          backgroundColor="transparent"
        />
      </box>

      {/* Last decline note */}
      {lastDeclineNote && (
        <box marginTop={1} marginLeft={2}>
          <text fg={colors.dimText} content={`Declined: ${lastDeclineNote}`} />
        </box>
      )}

      {/* Shortcuts hint */}
      <box flexDirection="row" gap={2} marginTop={1}>
        <text fg={colors.dimText} content="Y approve | A auto | Enter select" />
      </box>
    </box>
  );
}

export default ApprovalInputArea;
