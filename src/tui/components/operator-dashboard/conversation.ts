import type { ModelMessage } from "ai";
import type { DisplayMessage } from "../agent-display";

// ---------------------------------------------------------------------------
// Conversation transitions over ModelMessage[] — pure, immutable, testable
// ---------------------------------------------------------------------------

/**
 * Reconstruct a resumable assistant turn after an abort that landed before the
 * agent completed its first inference step (no assistant message persisted).
 * Returns null when the conversation already ends in an assistant response.
 */
export function recoverAbortedConversation(
  conversation: readonly ModelMessage[],
  partialText: string,
  displayMessages: readonly DisplayMessage[],
): ModelMessage[] | null {
  if (conversation.at(-1)?.role !== "user") return null;

  const pendingTools = displayMessages.filter(
    (
      message,
    ): message is DisplayMessage & {
      toolCallId: string;
      toolName: string;
      status: "pending" | "streaming";
    } =>
      message.role === "tool" &&
      typeof message.toolCallId === "string" &&
      typeof message.toolName === "string" &&
      (message.status === "pending" || message.status === "streaming"),
  );
  const assistantContent: Array<Record<string, unknown>> = [
    {
      type: "text" as const,
      text: partialText.trim() || "[Response interrupted by user.]",
    },
    ...pendingTools.map((tool) => ({
      type: "tool-call" as const,
      toolCallId: tool.toolCallId,
      toolName: tool.toolName,
      input: tool.args ?? {},
    })),
  ];
  const recovered: ModelMessage[] = [
    ...conversation,
    {
      role: "assistant",
      content: assistantContent,
    } as ModelMessage,
  ];

  if (pendingTools.length === 0) return recovered;

  return [
    ...recovered,
    {
      role: "tool",
      content: pendingTools.map((tool) => ({
        type: "tool-result" as const,
        toolCallId: tool.toolCallId,
        toolName: tool.toolName ?? "unknown",
        output: {
          type: "text" as const,
          value: "Cancelled by user.",
        },
      })),
    } as unknown as ModelMessage,
  ];
}

/**
 * Overwrite the output of the tool-result part matching `toolCallId` with a
 * JSON-wrapped value, leaving every other message and part untouched. Used for
 * ask-user-question answers, where Bedrock/Anthropic require the
 * `{ type: 'json', value }` wrapper. Returns the input unchanged (same
 * reference) when no part matches.
 */
export function rewriteToolResultOutput(
  conversation: readonly ModelMessage[],
  toolCallId: string,
  value: Record<string, unknown>,
): ModelMessage[] {
  const wrappedOutput = {
    type: "json" as const,
    value,
  };

  let changed = false;
  const next = conversation.map((msg) => {
    if (msg.role !== "tool") return msg;
    if (!Array.isArray(msg.content)) return msg;
    let mutated = false;
    const nextContent = msg.content.map((part) => {
      if (
        part &&
        typeof part === "object" &&
        "type" in part &&
        (part as { type?: unknown }).type === "tool-result" &&
        (part as { toolCallId?: unknown }).toolCallId === toolCallId
      ) {
        mutated = true;
        return {
          ...(part as Record<string, unknown>),
          output: wrappedOutput,
        };
      }
      return part;
    });
    if (!mutated) return msg;
    changed = true;
    return { ...msg, content: nextContent } as ModelMessage;
  });

  return changed ? next : (conversation as ModelMessage[]);
}
