import os from "node:os";
import { useAgent } from "../context/agent";
import { useDimensions } from "../context/dimensions";
import { useInput } from "../context/input";
import { useObfuscation } from "../context/obfuscation";
import { useSession } from "../context/session";
import { useActiveSessionUsage } from "../context/session-usage";
import { useTheme } from "../theme";
import { buildUsageFooterLabels } from "./usage-labels";

interface FooterProps {
  cwd?: string;
  showExitWarning?: boolean;
}

export default function Footer({
  cwd = process.cwd(),
  showExitWarning = false,
}: FooterProps) {
  const { colors } = useTheme();
  const { isExecuting, sessionCwd } = useAgent();
  const { width: termWidth } = useDimensions();
  const { enabled: obfuscateEnabled } = useObfuscation();
  const effectiveCwd = sessionCwd || cwd;
  const relativeCwd = effectiveCwd.split(os.homedir()).pop() || "";
  const segments = relativeCwd.split("/").filter(Boolean);
  const rawDisplayCwd =
    segments.length <= 2
      ? `~/${segments.join("/")}`
      : `…/${segments.slice(-2).join("/")}`;
  // When obfuscation is on, show a generic placeholder rather than leaking
  // the operator's local working directory in screenshots.
  const displayCwd = obfuscateEnabled ? "~/[workdir]" : rawDisplayCwd;
  const showCwd = termWidth >= 100;
  const session = useSession();
  const { isInputEmpty } = useInput();
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
        {showCwd && <text fg={colors.textMuted}>{displayCwd}</text>}
        <AgentStatus />
      </box>
      {showExitWarning ? (
        <box flexDirection="row" gap={1} flexShrink={0}>
          <text fg={colors.warning}>⚠ Press Ctrl+C again to exit</text>
        </box>
      ) : (
        <box flexDirection="row" gap={2} flexShrink={0}>
          {hotkeys.map((hotkey) => (
            <box key={hotkey.key} flexDirection="row" gap={1}>
              <text fg={colors.primary}>[{hotkey.key}]</text>
              <text fg={colors.textMuted}>{hotkey.label}</text>
            </box>
          ))}
        </box>
      )}
    </box>
  );
}

function AgentStatus() {
  const { colors } = useTheme();
  const { usageStore } = useAgent();
  const { width: termWidth } = useDimensions();
  const usage = useActiveSessionUsage(usageStore);

  const { tokensLabel, contextLabel } = buildUsageFooterLabels({
    tokenUsage: usage.tokenUsage,
    contextUsage: usage.contextUsage,
    width: termWidth,
  });

  if (!tokensLabel) return null;

  return (
    <box flexDirection="row" gap={1}>
      <text fg={colors.text}>{tokensLabel}</text>
      {contextLabel && (
        <>
          <text fg={colors.textMuted}>|</text>
          <text fg={colors.text}>{contextLabel}</text>
        </>
      )}
    </box>
  );
}
