/**
 * Shared Message Utilities
 *
 * Utilities for working with display messages in the TUI.
 */

import { createHash } from "crypto";
import type { DisplayMessage } from "../agent-display";
import { isToolMessage } from "./type-guards";

/**
 * Generate a short content hash for stable message keys.
 * Uses first 8 characters of SHA-256 hash.
 */
function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex").slice(0, 8);
}

/**
 * Generate a stable unique key for a message.
 *
 * Uses toolCallId for tool messages (most stable),
 * otherwise uses a combination of role, timestamp, and content hash.
 *
 * @param item - The display message
 * @param contextId - Optional context ID to prevent collisions across nested displays
 * @returns A stable unique key string
 */
export function getStableMessageKey(
  item: DisplayMessage,
  contextId: string = "root"
): string {
  // Tool messages use toolCallId (most stable identifier)
  if (isToolMessage(item)) {
    return `${contextId}-tool-${item.toolCallId}`;
  }

  // Other messages use role + timestamp + content hash
  const content =
    typeof item.content === "string"
      ? item.content
      : JSON.stringify(item.content);
  const contentHash = hashContent(content);
  return `${contextId}-${item.role}-${item.createdAt.getTime()}-${contentHash}`;
}

/**
 * Extract text content from a message.
 *
 * Handles string content, array content parts, and JSON objects.
 */
export function getMessageContent(message: DisplayMessage): string {
  if (typeof message.content === "string") {
    return message.content;
  } else if (Array.isArray(message.content)) {
    return message.content
      .map((part: any) => {
        if (typeof part === "string") return part;
        if (part.type === "text") return part.text;
        return JSON.stringify(part);
      })
      .join("");
  } else {
    return JSON.stringify(message.content, null, 2);
  }
}

/**
 * Format a result value for display (truncate if too long).
 */
export function formatResult(result: unknown, maxLength: number = 2000): string {
  try {
    const str = JSON.stringify(result, null, 2);
    if (str.length > maxLength) {
      return str.substring(0, maxLength) + "\n... (truncated)";
    }
    return str;
  } catch {
    return String(result);
  }
}
