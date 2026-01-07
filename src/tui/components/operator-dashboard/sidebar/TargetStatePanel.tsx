/**
 * Target State Panel - Shows host and discovered ports
 */

import { RGBA } from "@opentui/core";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);

interface TargetStatePanelProps {
  host: string;
  ports: { port: number; service?: string }[];
}

export function TargetStatePanel({ host, ports }: TargetStatePanelProps) {
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
