/**
 * Tool Renderer Component
 *
 * Unified tool display component for both operator and chat views.
 * Handles pending spinner, completion status, expandable output.
 */

import { memo, useState } from "react";
import { colors } from "../../theme";
import { AsciiSpinner } from "./ascii-spinner";
import { getToolSummary } from "./tool-registry";
import { getResultSummary, type ResultSummary } from "./result-registry";
import { isToolMessage, type ToolDisplayMessage } from "./type-guards";
import type { DisplayMessage } from "../agent-display";

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
  const [showOutput, setShowOutput] = useState(false);

  // Type guard ensures we have a tool message
  if (!isToolMessage(message)) {
    return null;
  }

  const isPending = message.status === "pending";
  const isCompleted = message.status === "completed";
  const isError = message.status === "error";
  const { toolName, args, result, logs } = message;

  // Get tool summary from registry
  const summary = getToolSummary(toolName, args);

  // Get result summary for completed tools
  const resultDisplay: ResultSummary | null =
    isCompleted || isError ? getResultSummary(result, toolName) : null;

  // Determine border color based on status
  const borderColor = isError
    ? colors.errorColor
    : isPending
    ? colors.yellowText
    : colors.toolColor;

  return (
    <box flexDirection="row" marginTop={0}>
      {/* Left border - distinguishes tool calls from assistant text */}
      <text fg={borderColor}>{"  │ "}</text>

      <box flexDirection="column">
        {/* Tool header line */}
        <box flexDirection="row" gap={1}>
          {isPending ? (
            <AsciiSpinner label={summary} fg={colors.yellowText} />
          ) : (
            <>
              <text fg={isError ? colors.errorColor : colors.successColor}>
                {isError ? "✗" : "✓"}
              </text>
              <text fg={colors.toolColor}>{summary}</text>
            </>
          )}
        </box>

        {/* Streaming logs while pending */}
        {isPending && logs && logs.length > 0 && (
          <box marginLeft={2}>
            <text fg={colors.dimText}>
              {expandedLogs ? logs.join("\n") : logs.slice(-2).join("\n")}
            </text>
          </box>
        )}

        {/* Result display for completed tools */}
        {(isCompleted || isError) && resultDisplay && (
          <box flexDirection="column" marginLeft={2}>
            {/* Summary line - always visible */}
            <box flexDirection="row" gap={1}>
              <text fg={resultDisplay.isError ? colors.errorColor : colors.dimText}>
                {resultDisplay.isError ? "✗" : "→"}
              </text>
              <text
                fg={resultDisplay.isError ? colors.errorColor : colors.creamText}
              >
                {resultDisplay.text}
              </text>
            </box>

            {/* Expandable output */}
            {resultDisplay.fullText && (verbose || showOutput) && (
              <box
                marginTop={0}
                onMouseDown={(e) => {
                  e.stopPropagation();
                  setShowOutput(!showOutput);
                }}
              >
                <text fg={colors.dimText}>
                  {showOutput ? "▼ output" : "▶ output"}
                </text>
                {showOutput && (
                  <box marginLeft={2} marginTop={0}>
                    <text fg={colors.dimText}>{resultDisplay.fullText}</text>
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
