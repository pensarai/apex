/**
 * Shared Message Utilities
 *
 * Utilities for working with display messages in the TUI.
 */

import type { DisplayMessage } from "../agent-display";
import { isToolMessage } from "./type-guards";

/**
 * Generate a stable unique key for a message.
 *
 * Uses toolCallId for tool messages (most stable),
 * otherwise uses role + timestamp. Content hash is intentionally
 * omitted so that streaming updates (which mutate content in-place)
 * don't change the key and cause React to remount the element,
 * which would reset the parent scrollbox's scroll position.
 *
 * @param item - The display message
 * @param contextId - Optional context ID to prevent collisions across nested displays
 * @returns A stable unique key string
 */
export function getStableMessageKey(
  item: DisplayMessage,
  contextId: string = "root",
): string {
  // Tool messages use toolCallId (most stable identifier)
  if (isToolMessage(item)) {
    return `${contextId}-tool-${item.toolCallId}`;
  }

  // Use role + timestamp only — content is intentionally excluded so that
  // streaming text deltas don't produce a new key on every frame.
  return `${contextId}-${item.role}-${item.createdAt.getTime()}`;
}

/**
 * Extract text content from a message.
 *
 * Handles string content, array content parts, and JSON objects.
 */
function getMessageContent(message: DisplayMessage): string {
  if (typeof message.content === "string") {
    return message.content;
  } else if (Array.isArray(message.content)) {
    return message.content
      .map((part: unknown) => {
        if (typeof part === "string") return part;
        if (
          typeof part === "object" &&
          part !== null &&
          "type" in part &&
          (part as Record<string, unknown>).type === "text"
        )
          return (part as Record<string, unknown>).text as string;
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
function formatResult(result: unknown, maxLength: number = 2000): string {
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

/**
 * Extract the primary text content from partially parsed tool args
 * for streaming display in the log window.
 */
export function extractStreamableContent(
  args: Record<string, unknown>,
): string | null {
  // create_file
  if (typeof args.content === "string") return args.content;
  // document_vulnerability — POC content
  if (typeof args.pocContent === "string") return args.pocContent;
  // update_file
  if (typeof args.newContent === "string") return args.newContent;
  // document_vulnerability — combine the key narrative fields
  if (typeof args.description === "string") {
    let text = args.description;
    if (typeof args.evidence === "string") text += "\n\n" + args.evidence;
    if (typeof args.impact === "string") text += "\n\n" + args.impact;
    if (typeof args.remediation === "string") text += "\n\n" + args.remediation;
    return text;
  }
  // add_memory — stream the title + content as it arrives
  if (typeof args.title === "string" && typeof args.content === "string") {
    return `${args.title}\n${args.content}`;
  }
  return null;
}

/**
 * Attempt to parse a partial JSON string produced by streaming tool-input deltas.
 *
 * Tries JSON.parse first. On failure, heuristically closes any unclosed
 * braces/brackets/strings and retries. Returns `null` if the string is
 * still unparseable (e.g. too little data has arrived).
 */
export function tryParsePartialJson(
  text: string,
): Record<string, unknown> | null {
  if (!text || !text.trimStart().startsWith("{")) return null;

  try {
    const result = JSON.parse(text);
    if (typeof result === "object" && result !== null) return result;
    return null;
  } catch {
    // Fall through to heuristic repair
  }

  let repaired = text;

  // Strip trailing comma (common in streaming)
  repaired = repaired.replace(/,\s*$/, "");

  // If we're inside a string value, close it
  const quoteCount = (repaired.match(/(?<!\\)"/g) || []).length;
  if (quoteCount % 2 !== 0) {
    repaired += '"';
  }

  // Close unclosed braces/brackets
  const opens: string[] = [];
  let inString = false;
  let escaped = false;
  for (const ch of repaired) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (ch === "{") opens.push("}");
    else if (ch === "[") opens.push("]");
    else if (ch === "}" || ch === "]") opens.pop();
  }

  // Strip trailing comma again after quote repair
  repaired = repaired.replace(/,\s*$/, "");

  for (let i = opens.length - 1; i >= 0; i--) {
    repaired += opens[i];
  }

  try {
    const result = JSON.parse(repaired);
    if (typeof result === "object" && result !== null) return result;
    return null;
  } catch {
    return null;
  }
}
