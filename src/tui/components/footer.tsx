import os from "os";
import { useAgent } from "../agentProvider";
import { ProgressBar, SpinnerDots } from "./sprites";

interface FooterProps {
  cwd?: string;
  showExitWarning?: boolean;
}

function formatTokenCount(count: number): string {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  } else if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
}

export default function Footer({
  cwd = process.cwd(),
  showExitWarning = false,
}: FooterProps) {
  cwd = "~" + cwd.split(os.homedir()).pop() || "";
  const { model, tokenCount, thinking, isExecuting } = useAgent();

  const hotkeys = isExecuting
    ? [{ key: "Ctrl+C", label: "Stop Execution" }]
    : [{ key: "Ctrl+C", label: "Clear/Exit" }];

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      width="100%"
      maxWidth="100%"
      flexShrink={0}
      border={true}
      borderColor="green"
    >
      <box flexDirection="row" gap={1}>
        <text fg="gray">{cwd}</text>
        <box border={["right"]} borderColor="green" />
        <text fg="gray">
          <span fg="white">{model.name}</span>
        </text>
        <AgentStatus />
      </box>
      {showExitWarning ? (
        <box flexDirection="row" gap={1}>
          <text fg="yellow">⚠ Press Ctrl+C again to exit</text>
        </box>
      ) : (
        <box flexDirection="row" gap={2}>
          {hotkeys.map((hotkey, index) => (
            <box key={index} flexDirection="row" gap={1}>
              <text fg="green">[{hotkey.key}]</text>
              <text fg="gray">{hotkey.label}</text>
            </box>
          ))}
        </box>
      )}
    </box>
  );
}

export function AgentStatus() {
  const { tokenCount, thinking, isExecuting } = useAgent();

  return (
    <box flexDirection="row" gap={1}>
      {tokenCount > 0 && (
        <>
          <box border={["right"]} borderColor="green" />
          <text fg="gray">
            ■ <span fg="white">{formatTokenCount(tokenCount)}</span>
          </text>
          <ContextProgress width={10} />
        </>
      )}
      {thinking && (
        <>
          <box border={["right"]} borderColor="green" />
          <SpinnerDots label="Thinking" fg="green" />
        </>
      )}
    </box>
  );
}

function ContextProgress({ width }: { width?: number }) {
  const { model, tokenCount, thinking } = useAgent();
  const contextProgress = Number(
    ((tokenCount / (model.contextLength ?? 200000)) * 100).toFixed(2)
  );
  if (!thinking) return null;
  return <ProgressBar value={contextProgress} width={width} />;
}
