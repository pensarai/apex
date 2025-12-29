import { RGBA } from "@opentui/core";
import type { PendingApproval, PermissionTier } from "../../../core/hitl";
import { PERMISSION_TIERS } from "../../../core/hitl";

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);

function getTierColor(tier: PermissionTier) {
  switch (tier) {
    case 1:
    case 2:
      return greenBullet;
    case 3:
      return yellowText;
    case 4:
      return orangeText;
    case 5:
      return redText;
  }
}

interface ApprovalPromptProps {
  approval: PendingApproval;
  onApprove: () => void;
  onDeny: () => void;
  focused?: boolean;
}

export default function ApprovalPrompt({ approval, onApprove, onDeny, focused = true }: ApprovalPromptProps) {
  const tierDef = PERMISSION_TIERS[approval.tier];
  const tierColor = getTierColor(approval.tier);

  // Format args for display (truncate long values)
  const formatArgs = (args: Record<string, unknown>): string => {
    const entries = Object.entries(args).slice(0, 3);
    return entries
      .map(([k, v]) => {
        const strVal = typeof v === "string" ? v : JSON.stringify(v);
        const truncated = strVal.length > 50 ? strVal.slice(0, 47) + "..." : strVal;
        return `${k}: ${truncated}`;
      })
      .join(", ");
  };

  return (
    <box
      flexDirection="column"
      border
      borderColor={tierColor}
      padding={1}
      gap={1}
    >
      <box flexDirection="row" gap={2}>
        <text fg={creamText}>⚠ Approval Required</text>
        <box backgroundColor={tierColor} paddingLeft={1} paddingRight={1}>
          <text fg="black">T{approval.tier}</text>
        </box>
        <text fg={dimText}>{tierDef.name}</text>
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={creamText}>Tool: {approval.toolName}</text>
        <text fg={dimText}>{formatArgs(approval.args)}</text>
      </box>

      {focused && (
        <box flexDirection="row" gap={2}>
          <text>
            <span fg={greenBullet}>[Y]</span>
            <span fg={dimText}> Approve</span>
          </text>
          <text>
            <span fg={redText}>[N]</span>
            <span fg={dimText}> Deny</span>
          </text>
          <text>
            <span fg={yellowText}>[A]</span>
            <span fg={dimText}> Auto-approve T{approval.tier}</span>
          </text>
        </box>
      )}
    </box>
  );
}
