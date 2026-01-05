/**
 * Suggestions Panel - Shows [1]/[2]/[3] options from agent
 */

import { RGBA } from "@opentui/core";
import type { Suggestion } from "../types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);

interface SuggestionsPanelProps {
  suggestions: Suggestion[];
  onSelect?: (suggestion: Suggestion) => void;
}

export function SuggestionsPanel({ suggestions }: SuggestionsPanelProps) {
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
