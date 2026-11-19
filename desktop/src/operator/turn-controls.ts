import type { OperatorMessage } from "./contract";

export function runningCommandId(
  messages: Pick<
    OperatorMessage,
    "role" | "toolName" | "toolCallId" | "status"
  >[],
): string | undefined {
  return messages.find(
    (message) =>
      message.role === "tool" &&
      message.toolName === "execute_command" &&
      (message.status === "pending" || message.status === "running"),
  )?.toolCallId;
}
