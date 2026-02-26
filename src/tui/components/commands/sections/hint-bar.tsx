import { useTheme } from "../../../theme";

interface HintItem {
  key: string;
  label: string;
}

interface HintBarProps {
  hints: HintItem[];
}

export function HintBar({ hints }: HintBarProps) {
  const { colors } = useTheme();
  return (
    <box flexDirection="column" gap={0} marginTop={1}>
      {hints.map((hint) => (
        <text key={hint.key}>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.textMuted}>Press </span>
          <span fg={colors.text}>[{hint.key}]</span>
          <span fg={colors.textMuted}> {hint.label}</span>
        </text>
      ))}
    </box>
  );
}
