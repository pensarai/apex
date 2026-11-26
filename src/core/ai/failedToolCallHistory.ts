import {
  type ModelMessage,
  NoSuchToolError,
  type ToolCallPart,
  type ToolResultPart,
} from "ai";

type FailedCall = { toolCallId: string; toolName: string; error?: unknown };

/** Project SDK-confirmed unknown calls as evidence, never as executable names. */
export function projectFailedToolCalls(
  messages: ModelMessage[],
  calls: readonly FailedCall[],
): ModelMessage[] {
  const unknown = new Map(
    calls
      .filter((call) => NoSuchToolError.isInstance(call.error))
      .map((call) => [call.toolCallId, call.toolName]),
  );
  if (unknown.size === 0) return messages;
  const attempted = new Map<string, ToolCallPart>();
  for (const message of messages) {
    if (message.role !== "assistant" || typeof message.content === "string")
      continue;
    for (const part of message.content) {
      if (
        part.type === "tool-call" &&
        unknown.get(part.toolCallId) === part.toolName
      )
        attempted.set(part.toolCallId, part);
    }
  }
  const rejected = new Map<
    string,
    { call: ToolCallPart; output: ToolResultPart["output"] }
  >();
  for (const message of messages) {
    if (message.role !== "tool") continue;
    for (const part of message.content) {
      if (
        part.type !== "tool-result" ||
        (part.output.type !== "error-text" && part.output.type !== "error-json")
      )
        continue;
      const call = attempted.get(part.toolCallId);
      if (call?.toolName === part.toolName)
        rejected.set(part.toolCallId, { call, output: part.output });
    }
  }
  if (rejected.size === 0) return messages;
  for (const message of messages) {
    if (message.role !== "assistant" || typeof message.content === "string")
      continue;
    for (const part of message.content) {
      if (
        part.type === "tool-approval-request" &&
        rejected.has(part.toolCallId)
      )
        throw new Error(
          `Failed unknown tool call ${part.toolCallId} unexpectedly has an approval request`,
        );
    }
  }
  const evidence = (id: string) => {
    const entry = rejected.get(id);
    if (!entry) throw new Error(`Missing rejected tool call ${id}`);
    return {
      type: "text" as const,
      text: `[Tool call rejected; not executed]\n${JSON.stringify({ toolCallId: id, toolName: entry.call.toolName, input: entry.call.input, error: entry.output })}`,
    };
  };
  return messages.map((message): ModelMessage => {
    if (message.role === "assistant" && Array.isArray(message.content)) {
      return {
        ...message,
        content: message.content.map((part) =>
          part.type === "tool-call" &&
          rejected.get(part.toolCallId)?.call.toolName === part.toolName
            ? evidence(part.toolCallId)
            : part,
        ),
      };
    }
    if (message.role !== "tool") return message;
    const kept = message.content.filter(
      (part) =>
        part.type !== "tool-result" ||
        rejected.get(part.toolCallId)?.call.toolName !== part.toolName,
    );
    if (kept.length === message.content.length) return message;
    // Keep a trailing native approval response discoverable by the SDK and pinning.
    return kept.length
      ? { ...message, content: kept }
      : {
          role: "user",
          content: message.content.flatMap((part) =>
            part.type === "tool-result" ? [evidence(part.toolCallId)] : [],
          ),
        };
  });
}
