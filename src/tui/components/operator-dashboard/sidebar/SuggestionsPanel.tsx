/**
 * Suggestions Panel - Shows [1]/[2]/[3] options from agent
 */

import type { Suggestion } from "../types";
import { useTheme } from "../../../theme";

interface SuggestionsPanelProps {
  suggestions: Suggestion[];
  onSelect?: (suggestion: Suggestion) => void;
}

export function SuggestionsPanel({ suggestions }: SuggestionsPanelProps) {
  const { colors } = useTheme();

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.text}>Suggestions</text>

      {suggestions.length === 0 ? (
        <text fg={colors.textMuted}>Waiting for agent...</text>
      ) : (
        <>
          {suggestions.map((s) => (
            <box key={s.id} flexDirection="row" gap={1}>
              <text fg={colors.warning}>[{s.number}]</text>
              <text fg={colors.textMuted}>{truncateLabel(s.label, 22)}</text>
            </box>
          ))}
          <text fg={colors.textMuted}>
            Press 1-{suggestions.length} to select
          </text>
        </>
      )}
    </box>
  );
}

function truncateLabel(label: string, maxLen: number): string {
  if (label.length <= maxLen) return label;
  return label.slice(0, maxLen - 3) + "...";
}
