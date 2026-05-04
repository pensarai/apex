/**
 * Inline Approval Prompt Components
 *
 * Approval UI rendered inline within the chat flow.
 * Provides visual context for pending approvals.
 */

import { useTheme } from "../../theme";
import { getToolSummary } from "../shared/tool-registry";
import { IntentBadge } from "../shared/intent-badge";
import type { PendingApproval } from "../../../core/operator";

interface InlineApprovalPromptProps {
  approval: PendingApproval;
}

/**
 * Inline approval prompt — shows pending tool call awaiting approval.
 */
export function InlineApprovalPrompt({ approval }: InlineApprovalPromptProps) {
  const { colors } = useTheme();

  const description = approval.args?.toolCallDescription as string | undefined;
  const summary = getToolSummary(approval.toolName, approval.args || {});

  return (
    <box flexDirection="row" marginTop={1}>
      {/* Yellow left border for pending approval */}
      <text fg={colors.warning}>{"  │ "}</text>

      <box flexDirection="column">
        {description && (
          <box flexDirection="row" marginBottom={1}>
            <text fg={colors.text} content={description} />
          </box>
        )}

        {/* Approval line */}
        <box flexDirection="row" gap={1}>
          <text fg={colors.warning} content="?" />
          <IntentBadge approval={approval} />
          <text fg={colors.info} content={summary} />
        </box>

        {/* Reasoning line */}
        <box flexDirection="row" marginLeft={2} marginTop={1}>
          <text
            fg={colors.textMuted}
            content={approval.classification.reasoning}
          />
        </box>

        {/* Shortcut hints */}
        <box flexDirection="row" gap={2} marginLeft={2} marginTop={1}>
          <text fg={colors.primary}>Y</text>
          <text fg={colors.textMuted}>approve</text>
          <text fg={colors.secondary}>A</text>
          <text fg={colors.textMuted}>approve + auto-approve safe</text>
          <text fg={colors.textMuted}>or type to redirect</text>
        </box>
      </box>
    </box>
  );
}

export default InlineApprovalPrompt;
