/**
 * Target State Panel - Shows host and discovered ports
 */

import { useTheme } from "../../../theme";

interface TargetStatePanelProps {
  host: string;
  ports: { port: number; service?: string }[];
}

export function TargetStatePanel({ host, ports }: TargetStatePanelProps) {
  const { colors } = useTheme();
  const portsStr = ports.length > 0 ? ports.map((p) => p.port).join(", ") : "—";

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.text}>Target</text>

      {/* Host */}
      <text fg={colors.primary}>{host}</text>

      {/* Ports */}
      <box flexDirection="row" gap={1}>
        <text fg={colors.textMuted}>Ports:</text>
        <text fg={colors.textMuted}>{portsStr}</text>
      </box>
    </box>
  );
}
