import type { ModelMessage } from "ai";

/**
 * Replace old tool-result outputs with a short placeholder to bound context growth.
 *
 * The last `keepRecentN` tool results (by order of appearance) are preserved in
 * full. Older results have their `output` replaced with a terse cleared marker.
 * Message count, ordering, and tool_use/tool_result pairing are never altered —
 * only the `output` field inside `ToolResultPart` entries is swapped.
 *
 * Returns a shallow copy of the array with deep-copied tool messages only
 * (assistant / user / system messages are shared by reference).
 */
export function compactToolResults(
  messages: ModelMessage[],
  keepRecentN = 6,
): ModelMessage[] {
  // --- Pass 1: collect toolCallIds of the last N results (reverse scan) ---
  const keepIds = new Set<string>();
  let seen = 0;

  for (let i = messages.length - 1; i >= 0 && seen < keepRecentN; i--) {
    const msg = messages[i];
    if (msg.role !== "tool") continue;
    for (let j = msg.content.length - 1; j >= 0 && seen < keepRecentN; j--) {
      const part = msg.content[j];
      if (part.type === "tool-result") {
        keepIds.add(part.toolCallId);
        seen++;
      }
    }
  }

  // Nothing to clear — return as-is
  if (seen <= keepRecentN && keepIds.size === seen) {
    // Check if there are any tool results outside the keep set
    let totalResults = 0;
    for (const msg of messages) {
      if (msg.role === "tool") {
        for (const part of msg.content) {
          if (part.type === "tool-result") totalResults++;
        }
      }
    }
    if (totalResults <= keepRecentN) return messages;
  }

  // --- Pass 2: build compacted copy ---
  return messages.map((msg) => {
    if (msg.role !== "tool") return msg;

    const newContent = msg.content.map((part) => {
      if (part.type !== "tool-result") return part;
      if (keepIds.has(part.toolCallId)) return part;

      return {
        ...part,
        output: {
          type: "text" as const,
          value: `[Cleared: ${part.toolName}]`,
        },
      };
    });

    return { ...msg, content: newContent };
  });
}
