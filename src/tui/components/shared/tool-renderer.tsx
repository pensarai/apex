/**
 * Tool Renderer Component
 *
 * Unified tool display component for both operator and chat views.
 * Handles pending spinner, completion status, expandable output.
 */

import { memo, useState } from "react";
import { useTheme } from "../../theme";
import { AsciiSpinner } from "./ascii-spinner";
import { getToolSummary } from "./tool-registry";
import { getResultSummary, type ResultSummary } from "./result-registry";
import { isToolMessage } from "./type-guards";
import type { DisplayMessage } from "../agent-display";

const TOOLS_WITH_LOG_WINDOW = new Set([
  "execute_command",
  "run_attack_surface",
  "spawn_coding_agent",
  "spawn_pentest_swarm",
  "delegate_to_auth_subagent",
  "create_file",
  "create_poc",
]);

interface ToolRendererProps {
  message: DisplayMessage;
  verbose?: boolean;
  expandedLogs?: boolean;
}

/**
 * Tool Renderer - displays tool calls with status, spinner, and results.
 */
export const ToolRenderer = memo(function ToolRenderer({
  message,
  verbose = false,
  expandedLogs = false,
}: ToolRendererProps) {
  const { colors } = useTheme();
  const [showOutput, setShowOutput] = useState(false);

  // Type guard ensures we have a tool message
  if (!isToolMessage(message)) {
    return null;
  }

  const isStreaming = message.status === "streaming";
  const isPending = message.status === "pending" || isStreaming;
  const isCompleted = message.status === "completed";
  const isError = message.status === "error";
  const { toolName, args, result, logs } = message;

  // Get tool summary from registry
  const summary = getToolSummary(toolName, args);

  // Get result summary for completed tools
  const resultDisplay: ResultSummary | null =
    isCompleted || isError ? getResultSummary(result, toolName, args) : null;

  // Determine border color based on status
  const borderColor = isError
    ? colors.error
    : isPending
      ? colors.warning
      : colors.info;

  return (
    <box flexDirection="row" marginTop={0}>
      {/* Left border - distinguishes tool calls from assistant text */}
      <text fg={borderColor}>{"  │ "}</text>

      <box flexDirection="column">
        {/* Tool header line */}
        <box flexDirection="row" gap={1}>
          {isPending ? (
            <AsciiSpinner label={summary} fg={colors.warning} />
          ) : (
            <>
              <text fg={isError ? colors.error : colors.success}>
                {isError ? "✗" : "✓"}
              </text>
              <text fg={colors.info}>{summary}</text>
            </>
          )}
        </box>

        {/* Streaming log window for tools with live output */}
        {isPending &&
          TOOLS_WITH_LOG_WINDOW.has(toolName) &&
          logs &&
          logs.length > 0 && (
            <box flexDirection="column" marginLeft={0} marginTop={0}>
              <text fg={colors.textMuted}>{"  ┌─"}</text>
              <box marginLeft={0}>
                <text fg={colors.textMuted}>
                  {"  │ "}
                  {(expandedLogs ? logs : logs.slice(-15)).join("\n  │ ")}
                </text>
              </box>
              <text fg={colors.textMuted}>{"  └─"}</text>
            </box>
          )}

        {/* Streaming logs for other pending tools */}
        {isPending &&
          !TOOLS_WITH_LOG_WINDOW.has(toolName) &&
          logs &&
          logs.length > 0 && (
            <box marginLeft={2}>
              <text fg={colors.textMuted}>
                {expandedLogs ? logs.join("\n") : logs.slice(-2).join("\n")}
              </text>
            </box>
          )}

        {/* Result display for completed tools */}
        {(isCompleted || isError) && resultDisplay && (
          <box flexDirection="column" marginLeft={2}>
            {/* Label + indicator */}
            <box flexDirection="row" gap={1}>
              <text
                fg={resultDisplay.isError ? colors.error : colors.textMuted}
              >
                {resultDisplay.isError ? "✗" : "→"}
              </text>
              {resultDisplay.styledText ? (
                resultDisplay.label ? (
                  <text fg={colors.textMuted}>{resultDisplay.label}</text>
                ) : null
              ) : (
                <text fg={resultDisplay.isError ? colors.error : colors.text}>
                  {resultDisplay.text}
                </text>
              )}
            </box>

            {/* Syntax-highlighted code preview */}
            {resultDisplay.styledText && (
              <text content={resultDisplay.styledText} />
            )}

            {/* Expandable output */}
            {resultDisplay.fullText && (verbose || showOutput) && (
              <box
                marginTop={0}
                onMouseDown={(e) => {
                  e.stopPropagation();
                  setShowOutput(!showOutput);
                }}
              >
                <text fg={colors.textMuted}>
                  {showOutput ? "▼ output" : "▶ output"}
                </text>
                {showOutput && (
                  <box marginLeft={2} marginTop={0}>
                    <text fg={colors.textMuted}>{resultDisplay.fullText}</text>
                  </box>
                )}
              </box>
            )}
          </box>
        )}
      </box>
    </box>
  );
});

export default ToolRenderer;
