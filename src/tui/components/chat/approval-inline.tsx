/**
 * Inline Approval Prompt Components
 *
 * Approval UI rendered inline within the chat flow.
 * Provides visual context for pending approvals.
 */

import { colors, getTierColor } from "../../theme";
import { getToolSummary } from "../shared/tool-registry";
import type { PendingApproval } from "../../../core/operator";

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
    <box flexDirection="row" marginTop={1}>
      {/* Yellow left border for pending approval */}
      <text fg={colors.yellowText}>{"  │ "}</text>

      <box flexDirection="column">
        {/* Description from agent if available */}
        {description && (
          <box flexDirection="row" marginBottom={1}>
            <text fg={colors.creamText} content={description} />
          </box>
        )}

        {/* Approval line with tier indicator */}
        <box flexDirection="row" gap={1}>
          <text fg={colors.yellowText} content="?" />
          <text fg={tierColor} content={`[T${approval.tier}]`} />
          <text fg={colors.toolColor} content={summary} />
        </box>

        {/* Shortcut hints */}
        <box flexDirection="row" gap={2} marginLeft={2} marginTop={1}>
          <text fg={colors.greenAccent}>Y</text>
          <text fg={colors.dimText}>approve</text>
          <text fg={colors.cyanAccent}>A</text>
          <text fg={colors.dimText}>auto-approve</text>
          <text fg={colors.dimText}>or type to redirect</text>
        </box>
      </box>
    </box>
  );
}

export default InlineApprovalPrompt;
