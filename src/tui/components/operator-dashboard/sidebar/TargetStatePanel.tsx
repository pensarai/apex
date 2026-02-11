/**
 * Target State Panel - Shows host and discovered ports
 */

import { useColors } from "../../../theme";

interface TargetStatePanelProps {
  host: string;
  ports: { port: number; service?: string }[];
}

export function TargetStatePanel({ host, ports }: TargetStatePanelProps) {
  const colors = useColors();
  const { creamText, dimText, greenAccent } = colors;
  const portsStr = ports.length > 0
    ? ports.map(p => p.port).join(", ")
    : "—";

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>Target</text>

      {/* Host */}
      <text fg={greenAccent}>{host}</text>

      {/* Ports */}
      <box flexDirection="row" gap={1}>
        <text fg={dimText}>Ports:</text>
        <text fg={dimText}>{portsStr}</text>
      </box>
    </box>
  );
}
