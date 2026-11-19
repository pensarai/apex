import { describe, expect, it } from "vitest";
import type { OperatorMessage } from "./contract";
import { runningCommandId } from "./turn-controls";

const command = (
  toolCallId: string,
  status: string,
  toolName = "execute_command",
): OperatorMessage => ({
  role: "tool",
  toolCallId,
  status,
  toolName,
  content: "",
  createdAt: "now",
});

describe("running command controls", () => {
  it("targets the first executable command, not argument streaming, unrelated tools or queued commands", () => {
    const messages = [
      command("done", "completed"),
      command("http", "pending", "http_request"),
      command("arguments", "streaming"),
      command("active", "pending"),
      command("queued", "pending"),
    ];
    expect(runningCommandId(messages)).toBe("active");
    expect(
      runningCommandId(
        messages.map((message) =>
          message.toolCallId === "active"
            ? { ...message, status: "completed" }
            : message,
        ),
      ),
    ).toBe("queued");
    expect(
      runningCommandId([
        command("failed", "error"),
        command("cancelled", "cancelled"),
      ]),
    ).toBeUndefined();
  });
});
