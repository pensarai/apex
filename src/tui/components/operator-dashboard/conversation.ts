import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { getResumeMessages, normalizeMessages } from "../../../core/session";
import type { DisplayMessage } from "../agent-display";

// ---------------------------------------------------------------------------
// Conversation transitions over ModelMessage[] — pure, immutable, testable —
// plus the one concrete abort transcript operation that orchestrates them.
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

// ---------------------------------------------------------------------------
// Abort transcript recovery operation
// ---------------------------------------------------------------------------

export interface RecoverAbortedTranscriptInput {
  /** Session root — `messages.json` is read from and written here. */
  rootPath: string;
  /** In-memory conversation — the base when no usable transcript is on disk. */
  conversation: readonly ModelMessage[];
  /** Partial streamed assistant text at abort time. */
  partialText: string;
  /** Display messages — the source of pending/streaming tool state. */
  displayMessages: readonly DisplayMessage[];
}

/**
 * The abort-path transcript operation: read the persisted messages, reload the
 * resumable window into a normalized conversation, recover the aborted turn
 * via {@link recoverAbortedConversation}, and persist the corrected transcript
 * when recovery produced one. Best-effort throughout — read and write failures
 * keep whatever conversation is already available.
 *
 * Returns the conversation the caller should hold next: the recovered
 * transcript when recovery fired, otherwise the (possibly reloaded) input.
 */
export function recoverAbortedTranscript(
  input: RecoverAbortedTranscriptInput,
): ModelMessage[] {
  const messagesPath = join(input.rootPath, "messages.json");
  let conversation = input.conversation as ModelMessage[];
  let recovered: ModelMessage[] | null = null;

  try {
    if (existsSync(messagesPath)) {
      const raw = JSON.parse(readFileSync(messagesPath, "utf-8"));
      if (Array.isArray(raw) && raw.length > 0) {
        conversation = normalizeMessages(getResumeMessages(raw));
      }
    }
    recovered = recoverAbortedConversation(
      conversation,
      input.partialText,
      input.displayMessages,
    );
  } catch {
    // Best-effort read — keep whatever conversation we already have.
  }

  if (!recovered) return conversation;
  conversation = recovered;
  try {
    // Persist so session resume also sees the corrected state.
    writeFileSync(messagesPath, JSON.stringify(recovered, null, 2));
  } catch {
    // Best-effort write — the in-memory conversation is still recovered.
  }
  return conversation;
}
