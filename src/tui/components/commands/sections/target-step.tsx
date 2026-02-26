import Input from "../../input";
import { useTheme } from "../../../theme";
import { HintBar } from "./hint-bar";

interface TargetStepProps {
  title: string;
  /** Optional subtitle shown below the title */
  subtitle?: string;
  /** Optional model info line (e.g., "Model: claude-3 [default]") */
  modelInfo?: string;
  /** Session name value */
  name: string;
  /** Target URL value */
  target: string;
  /** Error message to display */
  error?: string | null;
  /** Which field is focused (0=name, 1=target, then wizard-specific fields) */
  focusedField: number;
  onNameChange: (value: string) => void;
  onTargetChange: (value: string) => void;
  /** Hint items for the bottom bar */
  hints: Array<{ key: string; label: string }>;
  /** Optional extra content rendered between inputs and hints (e.g., source code toggle) */
  children?: React.ReactNode;
}

export function TargetStep({
  title,
  subtitle,
  modelInfo,
  name,
  target,
  error,
  focusedField,
  onNameChange,
  onTargetChange,
  hints,
  children,
}: TargetStepProps) {
  const { colors } = useTheme();
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      <text fg={colors.text}>{title}</text>
      {subtitle && <text fg={colors.textMuted}>{subtitle}</text>}
      {modelInfo && <text fg={colors.textMuted}>{modelInfo}</text>}

      {error && <text fg={colors.error}>Error: {error}</text>}

      <Input
        label="Session Name"
        description="Auto-generated, edit if desired"
        placeholder="swift-falcon"
        value={name}
        onInput={onNameChange}
        focused={focusedField === 0}
      />

      <Input
        label="Target URL"
        description="e.g., https://example.com"
        placeholder="https://example.com"
        value={target}
        onInput={onTargetChange}
        focused={focusedField === 1}
      />

      {children}

      <HintBar hints={hints} />
    </box>
  );
}
