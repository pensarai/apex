import { useTheme } from "../../theme";

interface QueuedMessagesProps {
  messages: string[];
  selectedIndex: number;
}

export function QueuedMessages({
  messages,
  selectedIndex,
}: QueuedMessagesProps) {
  const { colors } = useTheme();

  if (messages.length === 0) return null;

  return (
    <box
      flexDirection="column"
      paddingLeft={2}
      paddingRight={2}
      paddingBottom={1}
      flexShrink={0}
    >
      <box flexDirection="row" gap={1} marginBottom={0}>
        <text fg={colors.textMuted}>Queued ({messages.length})</text>
      </box>
      {messages.map((msg, index) => {
        const isSelected = index === selectedIndex;
        const displayText = msg.length > 80 ? msg.slice(0, 77) + "…" : msg;
        return (
          // biome-ignore lint/suspicious/noArrayIndexKey: plain string queue, position is the identity
          <box key={`q-${index}`} flexDirection="row" gap={1}>
            <text fg={isSelected ? colors.primary : colors.textMuted}>
              {isSelected ? "▸" : " "}
            </text>
            <text fg={isSelected ? colors.text : colors.textMuted}>
              {displayText}
            </text>
          </box>
        );
      })}
      <box flexDirection="row" gap={2} marginTop={0}>
        <text fg={colors.textMuted}>
          ↑↓ select • Enter send now • ⌫ delete • e edit
        </text>
      </box>
    </box>
  );
}
