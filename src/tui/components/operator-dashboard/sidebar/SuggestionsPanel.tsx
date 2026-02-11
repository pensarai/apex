/**
 * Suggestions Panel - Shows [1]/[2]/[3] options from agent
 */

import type { Suggestion } from "../types";
import { useColors } from "../../../theme";

interface SuggestionsPanelProps {
  suggestions: Suggestion[];
  onSelect?: (suggestion: Suggestion) => void;
}

export function SuggestionsPanel({ suggestions }: SuggestionsPanelProps) {
  const colors = useColors();
  const { creamText, dimText, yellowText } = colors;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>Suggestions</text>

      {suggestions.length === 0 ? (
        <text fg={dimText}>Waiting for agent...</text>
      ) : (
        <>
          {suggestions.map((s) => (
            <box key={s.id} flexDirection="row" gap={1}>
              <text fg={yellowText}>[{s.number}]</text>
              <text fg={dimText}>{truncateLabel(s.label, 22)}</text>
            </box>
          ))}
          <text fg={dimText}>Press 1-{suggestions.length} to select</text>
        </>
      )}
    </box>
  );
}

function truncateLabel(label: string, maxLen: number): string {
  if (label.length <= maxLen) return label;
  return label.slice(0, maxLen - 3) + "...";
}
