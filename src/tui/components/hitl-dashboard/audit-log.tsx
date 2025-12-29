import { RGBA } from "@opentui/core";
import type { ActionHistoryEntry, PermissionTier } from "../../../core/hitl";

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

function getDecisionIcon(decision: ActionHistoryEntry["decision"]) {
  switch (decision) {
    case "approved":
      return { icon: "✓", color: greenBullet };
    case "auto-approved":
      return { icon: "⚡", color: yellowText };
    case "denied":
      return { icon: "✗", color: redText };
  }
}

interface AuditLogProps {
  history: ActionHistoryEntry[];
  maxItems?: number;
}

export default function AuditLog({ history, maxItems = 10 }: AuditLogProps) {
  const recentHistory = history.slice(-maxItems).reverse();

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>Audit Log</text>
      <box flexDirection="column" gap={0}>
        {recentHistory.length === 0 ? (
          <text fg={dimText}>No actions yet</text>
        ) : (
          recentHistory.map((entry) => {
            const { icon, color } = getDecisionIcon(entry.decision);
            const time = new Date(entry.timestamp).toLocaleTimeString();
            return (
              <box key={entry.id} flexDirection="row" gap={1}>
                <text fg={color}>{icon}</text>
                <text fg={dimText}>T{entry.tier}</text>
                <text fg={creamText}>{entry.toolName}</text>
              </box>
            );
          })
        )}
      </box>
    </box>
  );
}
