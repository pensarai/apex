import type { DisplayMessage } from "../agent-display";
import { extractStreamableContent } from "../shared/message-utils";
import { isToolMessage } from "../shared/type-guards";

/** Cap on retained command-output lines per tool message. */
export const MAX_LOG_LINES = 200;

export function appendStreamedText(
  messages: readonly DisplayMessage[],
  accumulated: string,
): DisplayMessage[] {
  const last = messages[messages.length - 1];
  if (last && last.role === "assistant") {
    const updated = [...messages];
    updated[updated.length - 1] = { ...last, content: accumulated };
    return updated;
  }
  return [
    ...messages,
    { role: "assistant", content: accumulated, createdAt: new Date() },
  ];
}

export function startStreamingToolCall(
  messages: readonly DisplayMessage[],
  toolCallId: string,
  toolName: string,
): DisplayMessage[] {
  return [
    ...messages,
    {
      role: "tool" as const,
      content: "",
      createdAt: new Date(),
      toolCallId,
      toolName,
      args: {},
      status: "streaming" as const,
    },
  ];
}

export function applyToolCallDelta(
  messages: readonly DisplayMessage[],
  toolCallId: string,
  parsed: Record<string, unknown>,
): DisplayMessage[] {
  const contentText = extractStreamableContent(parsed);
  const logs = contentText ? contentText.split("\n") : undefined;

  const idx = messages.findIndex(
    (m) => isToolMessage(m) && m.toolCallId === toolCallId,
  );
  if (idx === -1) return messages as DisplayMessage[];
  const updated = [...messages];
  updated[idx] = { ...updated[idx], args: parsed, ...(logs && { logs }) };
  return updated;
}

export function applyToolCall(
  messages: readonly DisplayMessage[],
  toolCallId: string,
  toolName: string,
  args?: Record<string, unknown>,
): DisplayMessage[] {
  const idx = messages.findIndex(
    (m) => isToolMessage(m) && m.toolCallId === toolCallId,
  );
  if (idx !== -1) {
    const updated = [...messages];
    updated[idx] = {
      ...updated[idx],
      args,
      logs: undefined,
      status: "pending" as const,
    };
    return updated;
  }
  return [
    ...messages,
    {
      role: "tool" as const,
      content: "",
      createdAt: new Date(),
      toolCallId,
      toolName,
      args,
      status: "pending" as const,
    },
  ];
}

export function applyToolResult(
  messages: readonly DisplayMessage[],
  toolCallId: string,
  result?: unknown,
): DisplayMessage[] {
  const idx = messages.findIndex(
    (m) => isToolMessage(m) && m.toolCallId === toolCallId,
  );
  if (idx === -1) return messages as DisplayMessage[];
  const updated = [...messages];
  updated[idx] = { ...updated[idx], status: "completed", result };
  return updated;
}

export function mergeCommandOutput(
  messages: readonly DisplayMessage[],
  buf: string,
): DisplayMessage[] {
  const idx = messages.findLastIndex(
    (m) =>
      isToolMessage(m) && (m.status === "pending" || m.status === "streaming"),
  );
  if (idx === -1) return messages as DisplayMessage[];

  const msg = messages[idx];
  const existing = msg.logs ?? [];
  const incoming = buf.split("\n");
  // If last existing line was partial (no trailing newline), merge it
  let merged: string[];
  if (existing.length > 0 && !buf.startsWith("\n")) {
    merged = [...existing];
    merged[merged.length - 1] += incoming[0];
    merged.push(...incoming.slice(1));
  } else {
    merged = [...existing, ...incoming];
  }
  // Cap to last MAX_LOG_LINES
  if (merged.length > MAX_LOG_LINES) {
    merged = merged.slice(-MAX_LOG_LINES);
  }

  const updated = [...messages];
  updated[idx] = { ...msg, logs: merged };
  return updated;
}
