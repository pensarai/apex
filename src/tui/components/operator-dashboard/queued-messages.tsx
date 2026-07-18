import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import { getQueueWindow, type QueuedMessage } from "./queue";

interface QueuedMessagesProps {
  messages: QueuedMessage[];
  selectedIndex: number;
}

export function QueuedMessages({
  messages,
  selectedIndex,
}: QueuedMessagesProps) {
  const { colors } = useTheme();
  const { width } = useDimensions();

  if (messages.length === 0) return null;

  const window = getQueueWindow(messages, selectedIndex);
  const maxTextWidth = Math.max(12, width - 6);
  const range =
    messages.length > window.items.length
      ? ` · ${window.start + 1}–${window.end}`
      : "";

  return (
    <box
      flexDirection="column"
      paddingLeft={2}
      paddingRight={2}
      paddingBottom={1}
      flexShrink={0}
    >
      <box flexDirection="row" gap={1} marginBottom={0}>
        <text fg={colors.textMuted}>
          Queued ({messages.length}){range}
        </text>
      </box>
      {window.items.map(({ message: msg, index }) => {
        const isSelected = index === selectedIndex;
        const displayText =
          msg.text.length > maxTextWidth
            ? `${msg.text.slice(0, maxTextWidth - 1)}…`
            : msg.text;
        return (
          <box key={msg.id} flexDirection="row" gap={1}>
            <text fg={isSelected ? colors.primary : colors.textMuted}>
              {isSelected ? "▸" : " "}
            </text>
            <text fg={isSelected ? colors.text : colors.textMuted}>
              {displayText}
            </text>
          </box>
        );
      })}
      {selectedIndex >= 0 && (
        <box flexDirection="row" gap={2} marginTop={0}>
          <text fg={colors.textMuted}>
            [Enter] send · [⌫] delete · [E] edit
          </text>
        </box>
      )}
    </box>
  );
}
