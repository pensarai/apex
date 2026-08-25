import { describe, expect, it } from "vitest";
import type { DisplayMessage } from "../agent-display";
import {
  markSubagentsInterrupted,
  type SubagentSession,
} from "./subagent-state";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function toolMessage(
  status: "streaming" | "pending" | "completed" | "error",
  toolCallId = "tc-1",
): DisplayMessage {
  return {
    role: "tool",
    content: "execute_command",
    createdAt: new Date("2026-08-25T00:00:00Z"),
    toolCallId,
    toolName: "execute_command",
    args: {},
    status,
  };
}

function textMessage(text: string): DisplayMessage {
  return {
    role: "assistant",
    content: text,
    createdAt: new Date("2026-08-25T00:00:01Z"),
  };
}

function makeSession(
  overrides: Partial<SubagentSession> = {},
): SubagentSession {
  return {
    id: "sub-1",
    name: "Subagent 1",
    status: "running",
    spawnedAt: new Date("2026-08-25T00:00:00Z"),
    input: null,
    messages: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// markSubagentsInterrupted
// ---------------------------------------------------------------------------

describe("markSubagentsInterrupted", () => {
  it("marks a running session cancelled, leaving its settled messages untouched", () => {
    const msg = textMessage("working");
    const sessions = new Map([["sub-1", makeSession({ messages: [msg] })]]);

    const result = markSubagentsInterrupted(sessions);

    const session = result.get("sub-1");
    expect(session?.status).toBe("cancelled");
    // Settled messages pass through by reference.
    expect(session?.messages[0]).toBe(msg);
  });

  it("leaves settled sessions without in-flight tools untouched by reference", () => {
    const settled = makeSession({
      id: "sub-2",
      status: "completed",
      completedAt: new Date("2026-08-25T00:00:05Z"),
      messages: [toolMessage("completed")],
    });
    const sessions = new Map([["sub-2", settled]]);

    const result = markSubagentsInterrupted(sessions);

    expect(result.get("sub-2")).toBe(settled);
  });

  it("interrupts in-flight tools on a session that already settled", () => {
    const completedTool = toolMessage("completed", "tc-done");
    const pendingTool = toolMessage("pending", "tc-pending");
    const streamingTool = toolMessage("streaming", "tc-streaming");
    const sessions = new Map([
      [
        "sub-1",
        makeSession({
          status: "failed",
          messages: [completedTool, pendingTool, streamingTool],
        }),
      ],
    ]);

    const result = markSubagentsInterrupted(sessions);

    const session = result.get("sub-1");
    // Status is preserved — only the "running → cancelled" flip happens.
    expect(session?.status).toBe("failed");
    expect(session?.messages[0]).toBe(completedTool);
    expect(session?.messages[1]).toMatchObject({
      status: "error",
      result: "Interrupted",
      toolCallId: "tc-pending",
    });
    expect(session?.messages[2]).toMatchObject({
      status: "error",
      result: "Interrupted",
      toolCallId: "tc-streaming",
    });
  });

  it("flips status and interrupts tools together for a running session", () => {
    const sessions = new Map([
      [
        "sub-1",
        makeSession({
          messages: [textMessage("hi"), toolMessage("streaming")],
        }),
      ],
    ]);

    const result = markSubagentsInterrupted(sessions);

    const session = result.get("sub-1");
    expect(session?.status).toBe("cancelled");
    expect(session?.messages[1]).toMatchObject({
      status: "error",
      result: "Interrupted",
    });
  });

  it("returns the identical reference for an empty store", () => {
    const sessions = new Map<string, SubagentSession>();

    const result = markSubagentsInterrupted(sessions);

    expect(result).toBe(sessions);
  });

  it("returns the identical reference when nothing needs changing", () => {
    const sessions = new Map([
      ["sub-1", makeSession({ status: "completed", messages: [] })],
    ]);

    const result = markSubagentsInterrupted(sessions);

    expect(result).toBe(sessions);
  });

  it("preserves insertion order across changed and unchanged sessions", () => {
    const sessions = new Map([
      ["sub-a", makeSession({ id: "sub-a", status: "running" })],
      ["sub-b", makeSession({ id: "sub-b", status: "completed" })],
      ["sub-c", makeSession({ id: "sub-c", status: "failed" })],
    ]);

    const result = markSubagentsInterrupted(sessions);

    expect(Array.from(result.keys())).toEqual(["sub-a", "sub-b", "sub-c"]);
  });

  it("does not mutate the input map, sessions, or messages", () => {
    const pendingTool = toolMessage("pending");
    const session = makeSession({
      messages: [textMessage("working"), pendingTool],
    });
    const sessions = new Map([["sub-1", session]]);
    const originalMap = structuredClone(Object.fromEntries(sessions.entries()));

    markSubagentsInterrupted(sessions);

    expect(Object.fromEntries(sessions.entries())).toEqual(originalMap);
    expect(session.status).toBe("running");
    expect(pendingTool.status).toBe("pending");
    expect(pendingTool.result).toBeUndefined();
  });
});
