import os from "os";
import { useAgent } from "../context/agent";
import { ProgressBar, SpinnerDots } from "./sprites";
import { useSession } from "../context/session";
import { useRoute } from "../context/route";
import { useInput } from "../context/input";
import { useEffect } from "react";

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
  const { model, tokenUsage, hasExecuted, thinking, isExecuting } = useAgent();
  const session = useSession();
  const route = useRoute();
  const { isInputEmpty } = useInput();

  const hotkeys = isExecuting
    ? [{ key: "Ctrl+C", label: "Stop Execution" }]
    : [
        { key: "Ctrl+C", label: "Clear/Exit" },
        ...(isInputEmpty ? [{ key: "?", label: "Shortcuts" }] : [])
      ];

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      width="100%"
      maxWidth="100%"
      flexShrink={0}
    >
      <box flexDirection="row" gap={1}>
        <text fg="gray">{cwd}</text>
        <box border={["right"]} borderColor="green" />
        <text fg="gray">
          <span fg="white">{model.name}</span>
        </text>
        <AgentStatus />
        {
          route.data.type === "session" && session.active &&
          <text fg="white">
            Session:{' '}
            <span fg="gray">
              {session.active.name}
            </span>
          </text>
        }
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
  const { tokenUsage, hasExecuted, thinking, isExecuting } = useAgent();

  useEffect(() => {
    console.log(tokenUsage);
  }, [tokenUsage]);

  return (
    <box flexDirection="row" gap={1}>
      {hasExecuted && (
        <>
          <box border={["right"]} borderColor="green" />
          <text fg="white">{`↓${formatTokenCount(tokenUsage.inputTokens)} ↑${formatTokenCount(tokenUsage.outputTokens)} Σ${formatTokenCount(tokenUsage.totalTokens)}`}</text>
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
  const { model, tokenUsage, thinking } = useAgent();
  if (!thinking || tokenUsage.totalTokens === 0) return null;
  const contextLength = model.contextLength ?? 200000;
  const contextProgress = Math.max(0, Math.min(100, Number(
    ((tokenUsage.totalTokens / contextLength) * 100).toFixed(2)
  )));
  return <ProgressBar value={contextProgress} width={width} />;
}
