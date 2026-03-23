import os from "os";
import { useAgent } from "../context/agent";
import { ProgressBar, SpinnerDots } from "./sprites";
import { useSession } from "../context/session";
import { useRoute } from "../context/route";
import { useInput } from "../context/input";
import { useTheme } from "../theme";

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
  const { colors } = useTheme();
  const { isExecuting, sessionCwd } = useAgent();
  const effectiveCwd = sessionCwd || cwd;
  const relativeCwd = effectiveCwd.split(os.homedir()).pop() || "";
  const segments = relativeCwd.split("/").filter(Boolean);
  const displayCwd =
    segments.length <= 2
      ? "~/" + segments.join("/")
      : "…/" + segments.slice(-2).join("/");
  const session = useSession();
  const route = useRoute();
  const { isInputEmpty } = useInput();
  const isPentest = route.data.type === "pentest" && !route.data.openAsOperator;

  // Pentest footer: minimal — just navigation hints
  if (isPentest) {
    return (
      <box
        flexDirection="row"
        justifyContent="space-between"
        width="100%"
        maxWidth="100%"
        height={1}
        flexShrink={0}
        overflow="hidden"
      >
        <text fg={colors.textMuted}>{displayCwd}</text>
        <box flexDirection="row" gap={2} flexShrink={0}>
          <box flexDirection="row" gap={1}>
            <text fg={colors.primary}>[Tab]</text>
            <text fg={colors.textMuted}>Navigate</text>
          </box>
          <box flexDirection="row" gap={1}>
            <text fg={colors.primary}>[ESC]</text>
            <text fg={colors.textMuted}>Back</text>
          </box>
        </box>
      </box>
    );
  }

  const hotkeys = isExecuting
    ? [{ key: "Ctrl+C", label: "Stop Execution" }]
    : [
        { key: "Ctrl+C", label: "Clear/Exit" },
        ...(isInputEmpty ? [{ key: "?", label: "Shortcuts" }] : []),
      ];

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      width="100%"
      maxWidth="100%"
      height={1}
      flexShrink={0}
      overflow="hidden"
    >
      <box flexDirection="row" gap={1} flexShrink={1} overflow="hidden">
        <text fg={colors.textMuted}>{displayCwd}</text>
        <AgentStatus />
      </box>
      {showExitWarning ? (
        <box flexDirection="row" gap={1} flexShrink={0}>
          <text fg={colors.warning}>⚠ Press Ctrl+C again to exit</text>
        </box>
      ) : (
        <box flexDirection="row" gap={2} flexShrink={0}>
          {hotkeys.map((hotkey, index) => (
            <box key={index} flexDirection="row" gap={1}>
              <text fg={colors.primary}>[{hotkey.key}]</text>
              <text fg={colors.textMuted}>{hotkey.label}</text>
            </box>
          ))}
        </box>
      )}
    </box>
  );
}

export function AgentStatus() {
  const { colors } = useTheme();
  const route = useRoute();
  const { tokenUsage, hasExecuted, thinking } = useAgent();

  const tokenLabel =
    route.data.type === "operator"
      ? `${formatTokenCount(tokenUsage.outputTokens)}↑ ${formatTokenCount(tokenUsage.inputTokens)}↓`
      : `↓${formatTokenCount(tokenUsage.inputTokens)} ↑${formatTokenCount(tokenUsage.outputTokens)} Σ${formatTokenCount(tokenUsage.totalTokens)}`;

  return (
    <box flexDirection="row" gap={1}>
      {hasExecuted && (
        <>
          <box border={["right"]} borderColor={colors.primary} />
          <text fg={colors.text}>{tokenLabel}</text>
        </>
      )}
      {thinking && (
        <>
          <box border={["right"]} borderColor={colors.primary} />
          <SpinnerDots label="Thinking" fg={colors.primary} />
        </>
      )}
    </box>
  );
}

function ContextProgress({ width }: { width?: number }) {
  const { model, tokenUsage, thinking } = useAgent();
  if (!thinking || tokenUsage.totalTokens === 0) return null;
  const contextLength = model.contextLength ?? 200000;
  const contextProgress = Math.max(
    0,
    Math.min(
      100,
      Number(((tokenUsage.totalTokens / contextLength) * 100).toFixed(2)),
    ),
  );
  return <ProgressBar value={contextProgress} width={width} />;
}
