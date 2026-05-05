/**
 * Inline Approval Prompt Components
 *
 * Approval UI rendered inline within the chat flow.
 * Provides visual context for pending approvals.
 */

import { useTheme } from "../../theme";
import { getToolSummary } from "../shared/tool-registry";
import { deriveApprovedActionLabel } from "../shared/action-label";
import type { PendingApproval } from "../../../core/operator";

interface InlineApprovalPromptProps {
  approval: PendingApproval;
}

export function InlineApprovalPrompt({ approval }: InlineApprovalPromptProps) {
  const { colors } = useTheme();

  const label = deriveApprovedActionLabel(approval);
  const summary = getToolSummary(approval.toolName, approval.args || {});
  const showSummaryLine = summary !== label;

  return (
    <box flexDirection="row" marginTop={1}>
      {/* Yellow left border for pending approval */}
      <text fg={colors.warning}>{"  │ "}</text>

      <box flexDirection="column">
        <box flexDirection="row" marginBottom={showSummaryLine ? 1 : 0}>
          <text fg={colors.text} content={label} />
        </box>

        {showSummaryLine && (
          <box flexDirection="row" gap={1}>
            <text fg={colors.warning} content="?" />
            <text fg={colors.info} content={summary} />
          </box>
        )}

        {/* Shortcut hints */}
        <box flexDirection="row" gap={2} marginLeft={2} marginTop={1}>
          <text fg={colors.primary}>Y</text>
          <text fg={colors.textMuted}>approve</text>
          <text fg={colors.secondary}>A</text>
          <text fg={colors.textMuted}>approve all</text>
          <text fg={colors.textMuted}>or type to redirect</text>
        </box>
      </box>
    </box>
  );
}

export default InlineApprovalPrompt;
