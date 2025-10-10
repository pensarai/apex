import os from "os";
import { useAgent } from "../agentProvider";
import { SpinnerDots } from "./sprites";

interface FooterProps {
  cwd?: string;
  showExitWarning?: boolean;
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

  function formatTokenCount(count: number): string {
    if (count >= 1000000) {
      return `${(count / 1000000).toFixed(1)}M`;
    } else if (count >= 1000) {
      return `${(count / 1000).toFixed(1)}K`;
    }
    return count.toString();
  }

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
        {tokenCount > 0 && (
          <>
            <box border={["right"]} borderColor="green" />
            <text fg="gray">
              ■ <span fg="white">{formatTokenCount(tokenCount)}</span>
            </text>
          </>
        )}
        {thinking && (
          <>
            <box border={["right"]} borderColor="green" />
            <SpinnerDots label="Thinking" fg="green" />
          </>
        )}
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
