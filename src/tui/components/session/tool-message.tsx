/**
 * Enhanced Tool Message Component
 *
 * Enhanced tool rendering following OpenCode patterns:
 * - Compact summary line with spinner/status
 * - Expandable args and output
 * - Streaming logs support
 * - Category-aware icons
 */

import { memo, useState } from "react";
import { colors } from "../../theme";
import { AsciiSpinner } from "../shared/ascii-spinner";
import { getToolSummary } from "../shared/tool-registry";
import { getResultSummary, type ResultSummary } from "../shared/result-registry";
import { isToolMessage, type ToolDisplayMessage } from "../shared/type-guards";
import type { DisplayMessage } from "../agent-display";

// Tool category icons
const TOOL_ICONS: Record<string, string> = {
  http_request: "→",
  execute_command: "$",
  read_file: "□",
  write_file: "□",
  smart_enumerate: "◎",
  fuzz_endpoint: "~",
  sql_inject: "▶",
  auth_test: "◇",
  default: "·",
};

interface ToolMessageProps {
  message: DisplayMessage;
  verbose?: boolean;
  expandedLogs?: boolean;
}

/**
 * Enhanced tool message component with OpenCode-style rendering
 */
export const ToolMessage = memo(function ToolMessage({
  message,
  verbose = false,
  expandedLogs = false,
}: ToolMessageProps) {
  const [showArgs, setShowArgs] = useState(false);
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
    isCompleted || isError ? getResultSummary(result) : null;

  // Get tool icon
  const icon = TOOL_ICONS[toolName] || TOOL_ICONS.default;

  return (
    <box flexDirection="column" marginLeft={2} marginTop={0}>
      {/* Tool header line */}
      <box flexDirection="row" gap={1}>
        {isPending ? (
          <AsciiSpinner label={summary} />
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

      {/* Expandable args section */}
      {args && Object.keys(args).length > 0 && (verbose || showArgs) && (
        <box flexDirection="column" marginLeft={2}>
          <box
            flexDirection="row"
            gap={1}
            onMouseDown={(e) => {
              e.stopPropagation();
              setShowArgs(!showArgs);
            }}
          >
            <text fg={colors.dimText}>
              {showArgs ? "▼ args" : "▶ args"}
            </text>
          </box>
          {showArgs && (
            <box marginLeft={2}>
              <text fg={colors.dimText}>
                {formatArgs(args)}
              </text>
            </box>
          )}
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
          {resultDisplay.fullText && (
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
              {(verbose || showOutput) && (
                <box marginLeft={2} marginTop={0}>
                  <text fg={colors.dimText}>{resultDisplay.fullText}</text>
                </box>
              )}
            </box>
          )}
        </box>
      )}
    </box>
  );
});

/**
 * Format args object for display
 */
function formatArgs(args: Record<string, unknown>): string {
  // Filter out internal args like toolCallDescription
  const displayArgs = Object.entries(args).filter(
    ([key]) => !key.startsWith("toolCall")
  );

  if (displayArgs.length === 0) return "";

  return displayArgs
    .map(([key, value]) => {
      const valueStr =
        typeof value === "string"
          ? value.length > 80
            ? value.slice(0, 77) + "..."
            : value
          : JSON.stringify(value);
      return `${key}: ${valueStr}`;
    })
    .join("\n");
}

export default ToolMessage;
