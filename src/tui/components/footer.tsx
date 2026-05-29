import os from "node:os";
import type { RGBA } from "@opentui/core";
import { useAgent } from "../context/agent";
import { useDimensions } from "../context/dimensions";
import { useInput } from "../context/input";
import { useObfuscation } from "../context/obfuscation";
import { useSession } from "../context/session";
import { useTheme } from "../theme";
import { withAlpha } from "./loaders";

interface FooterProps {
  cwd?: string;
  showExitWarning?: boolean;
}

function formatTokenCount(count: number): string {
  // Drop the trailing `.0` for whole-number K/M values so round counts
  // render as `200K` / `1M` instead of `200.0K` / `1.0M`. Fractional
  // values keep one decimal (`1.2K`, `1.5M`).
  if (count >= 1_000_000) {
    const v = count / 1_000_000;
    return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}M`;
  }
  if (count >= 1000) {
    const v = count / 1000;
    return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}K`;
  }
  return count.toString();
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
      ? "~/" + segments.join("/")
      : "…/" + segments.slice(-2).join("/");
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

function AgentStatus() {
  const { colors } = useTheme();
  const { tokenUsage } = useAgent();
  const { width: termWidth } = useDimensions();
  const showTokenCount = termWidth > 85;

  const tokenLabel = `↓${formatTokenCount(tokenUsage.inputTokens)} ↑${formatTokenCount(tokenUsage.outputTokens)}${tokenUsage.cachedTokens > 0 ? ` ⚡${formatTokenCount(tokenUsage.cachedTokens)}` : ""} Σ${formatTokenCount(tokenUsage.totalTokens)}`;

  return (
    <box flexDirection="row" gap={1}>
      {showTokenCount && (
        <>
          <box border={["right"]} borderColor={colors.primary} />
          <text fg={colors.text}>{tokenLabel}</text>
          <box border={["right"]} borderColor={colors.primary} />
        </>
      )}
      <ContextProgress width={16} showPercent={true} />
    </box>
  );
}

const FILL_CHAR = "▬";
const DASH_CHAR = "─";

/**
 * `[ ███████  42% ─────]` style progress bar showing how much of the
 * model's context window has been consumed. The label is centered
 * inside the bracketed track and switches foreground color depending
 * on whether it sits over the filled or unfilled portion so it stays
 * legible at any progress level.
 *
 * @param width        Total cells including brackets.
 * @param showPercent  When true, prefix the label with `NN% ` so the
 *                     usage percentage is rendered alongside the
 *                     context window size.
 */
function ContextProgress({
  width = 20,
  showPercent = false,
}: {
  width?: number;
  showPercent?: boolean;
}) {
  const { colors } = useTheme();
  const { model, tokenUsage } = useAgent();

  const contextLength = model.contextLength ?? 200_000;
  const fraction = Math.max(
    0,
    Math.min(1, tokenUsage.totalTokens / contextLength),
  );

  const inner = Math.max(1, width - 2);
  const filledCells = Math.round(fraction * inner);

  const fillColor = colors.success;

  const sizeText = formatTokenCount(contextLength);
  const labelText = showPercent
    ? `${Math.floor(fraction * 100)}% ${sizeText}`
    : sizeText;
  const labelLen = labelText.length;
  // Right-aligned with a 1-cell breathing space from the closing bracket.
  const labelStart = Math.max(0, inner - labelLen - 1);
  const labelEnd = labelStart + labelLen;

  const dashColor = withAlpha(colors.textMuted, 0.35);
  const bracketColor = withAlpha(colors.textMuted, 0.7);

  type Cell = { ch: string; fg: RGBA };
  const cells: Cell[] = [];
  cells.push({ ch: "[", fg: bracketColor });
  for (let col = 0; col < inner; col++) {
    const inLabel = col >= labelStart && col < labelEnd;
    const isFilled = col < filledCells;
    if (inLabel) {
      cells.push({
        ch: labelText[col - labelStart]!,
        fg: colors.text,
      });
    } else if (isFilled) {
      cells.push({ ch: FILL_CHAR, fg: fillColor });
    } else {
      cells.push({ ch: DASH_CHAR, fg: dashColor });
    }
  }
  cells.push({ ch: "]", fg: bracketColor });

  return (
    <box flexDirection="row">
      {cells.map((cell, i) => (
        <text key={i} fg={cell.fg} content={cell.ch} />
      ))}
    </box>
  );
}
