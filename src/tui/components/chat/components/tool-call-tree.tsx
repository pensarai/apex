/**
 * Tool Call Tree Component
 *
 * Renders tool calls with tree structure for nested tasks.
 * Based on the design spec with ├─ └─ tree connectors.
 */

import { memo } from "react";
import { colors } from "../../../theme";
import { AsciiSpinner, getToolSummary as getToolSummaryFromRegistry } from "../../shared";

export interface ToolNode {
  id: string;
  name: string;
  summary?: string;
  args?: Record<string, unknown>;
  status: "pending" | "running" | "completed" | "error";
  children?: ToolNode[];
  result?: unknown;
  error?: string;
}

interface ToolCallTreeProps {
  node: ToolNode;
  isLast?: boolean;
  depth?: number;
}

/**
 * Get status indicator for a tool node
 */
function StatusIndicator({ status }: { status: ToolNode["status"] }) {
  switch (status) {
    case "pending":
      return <text fg={colors.dimText}>○</text>;
    case "running":
      return <text fg={colors.greenAccent}>●</text>;
    case "completed":
      return <text fg={colors.successColor}>○</text>;
    case "error":
      return <text fg={colors.errorColor}>✖</text>;
    default:
      return <text fg={colors.dimText}>○</text>;
  }
}

/**
 * Format tool summary based on tool name and args
 */
function getToolSummary(node: ToolNode): string {
  if (node.summary) return node.summary;
  return getToolSummaryFromRegistry(node.name, node.args || {});
}

export const ToolCallTree = memo(function ToolCallTree({
  node,
  isLast = true,
  depth = 0,
}: ToolCallTreeProps) {
  const hasChildren = node.children && node.children.length > 0;
  const isTask = node.name === "Task" || node.name === "task";
  const summary = getToolSummary(node);

  // Indentation and tree connectors
  const indent = depth > 0 ? "  ".repeat(depth - 1) : "";
  const connector = depth > 0 ? (isLast ? "└─" : "├─") : "";

  return (
    <box flexDirection="column" marginLeft={2}>
      {/* Main tool line */}
      <box flexDirection="row" gap={1}>
        {depth > 0 && <text fg={colors.dimText}>{indent}{connector}</text>}
        {node.status === "running" ? (
          <AsciiSpinner label={isTask ? `Task "${summary}"` : summary} />
        ) : (
          <box flexDirection="row" gap={1}>
            <StatusIndicator status={node.status} />
            <text
              fg={node.status === "completed" ? colors.dimText : colors.toolColor}
              content={isTask ? `Task "${summary}"` : summary}
            />
          </box>
        )}
      </box>

      {/* Children (subtasks) */}
      {hasChildren && (
        <box flexDirection="column">
          {node.children!.map((child, idx) => (
            <ToolCallTree
              key={child.id}
              node={child}
              isLast={idx === node.children!.length - 1}
              depth={depth + 1}
            />
          ))}
        </box>
      )}

      {/* Error display */}
      {node.status === "error" && node.error && (
        <box marginLeft={depth > 0 ? 4 : 2}>
          <text fg={colors.errorColor}>{`-> Error: ${node.error.slice(0, 60)}`}</text>
        </box>
      )}
    </box>
  );
});

/**
 * Flat tool call display (non-tree version for simple tools)
 */
interface FlatToolCallProps {
  name: string;
  summary: string;
  status: "pending" | "running" | "completed" | "error";
  result?: { text: string; isError: boolean } | null;
}

export function FlatToolCall({ name, summary, status, result }: FlatToolCallProps) {
  return (
    <box flexDirection="column" marginLeft={2}>
      <box flexDirection="row" gap={1}>
        {status === "running" ? (
          <AsciiSpinner label={summary} />
        ) : (
          <box flexDirection="row" gap={1}>
            <StatusIndicator status={status} />
            <text
              fg={status === "completed" ? colors.dimText : colors.toolColor}
              content={summary}
            />
          </box>
        )}
      </box>
      {status === "completed" && result && (
        <box marginLeft={2}>
          <text
            fg={result.isError ? colors.errorColor : colors.dimText}
            content={`-> ${result.text}`}
          />
        </box>
      )}
    </box>
  );
}

export default ToolCallTree;
