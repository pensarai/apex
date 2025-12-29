import { RGBA } from "@opentui/core";
import type { HITLStage } from "../../../core/hitl";
import { getSuggestedActions, type ActionSuggestion } from "../../../core/agent/hitlAgent/suggestActions";
import type { ActionHistoryEntry } from "../../../core/hitl";

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

interface SuggestedActionsProps {
  currentStage: HITLStage;
  actionHistory: ActionHistoryEntry[];
  target?: string;
  onSelectAction?: (directive: string) => void;
  focusedIndex?: number;
}

export default function SuggestedActions({
  currentStage,
  actionHistory,
  target,
  onSelectAction,
  focusedIndex = -1,
}: SuggestedActionsProps) {
  const suggestions = getSuggestedActions(currentStage, actionHistory, { target });

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>Suggestions</text>
      <box flexDirection="column" gap={0}>
        {suggestions.slice(0, 5).map((suggestion, idx) => {
          const isFocused = focusedIndex === idx;
          return (
            <box key={suggestion.id} flexDirection="row" gap={1}>
              <text fg={isFocused ? greenBullet : dimText}>
                {idx + 1}.
              </text>
              <text fg={isFocused ? creamText : dimText}>
                {suggestion.label}
              </text>
            </box>
          );
        })}
      </box>
      <text fg={dimText}>[1-5] Select suggestion</text>
    </box>
  );
}
