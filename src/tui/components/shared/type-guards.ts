/**
 * Type Guards for Display Messages
 *
 * TypeScript helpers for safely narrowing DisplayMessage types.
 * Eliminates `(m as any).status` casts throughout the codebase which agents love to use.
 */

import type { DisplayMessage, ToolStatus } from "../agent-display";

/**
 * Tool message with required tool-specific fields.
 * This interface represents a message where role === "tool" and all tool fields are present.
 */
export interface ToolDisplayMessage {
  role: "tool";
  content: string | unknown[];
  createdAt: Date;
  toolCallId: string;
  toolName: string;
  args: Record<string, unknown>;
  result?: unknown;
  status: ToolStatus;
  logs?: string[];
}

/**
 * Type guard for tool messages.
 * Narrows DisplayMessage to ToolDisplayMessage with full type safety.
 */
export function isToolMessage(msg: DisplayMessage): msg is ToolDisplayMessage {
  return (
    msg.role === "tool" &&
    typeof msg.toolCallId === "string" &&
    typeof msg.toolName === "string" &&
    typeof msg.status === "string"
  );
}

/**
 * Check if a message is a pending tool call.
 */
export function isPendingTool(msg: DisplayMessage): boolean {
  return isToolMessage(msg) && msg.status === "pending";
}

/**
 * Check if a message is a completed tool call.
 */
export function isCompletedTool(msg: DisplayMessage): boolean {
  return isToolMessage(msg) && msg.status === "completed";
}

/**
 * Check if a message is an errored tool call.
 */
export function isErroredTool(msg: DisplayMessage): boolean {
  return isToolMessage(msg) && msg.status === "error";
}
