import { describe, expect, it } from "vitest";
import type { DisplayMessage } from "../agent-display";
import {
  appendStreamedText,
  applyToolCall,
  applyToolCallDelta,
  applyToolResult,
  MAX_LOG_LINES,
  mergeCommandOutput,
  startStreamingToolCall,
} from "./display-state";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const userMessage: DisplayMessage = {
  role: "user",
  content: "scan the target",
  createdAt: new Date("2026-08-24T00:00:00Z"),
};

const streamingTool: DisplayMessage = {
  role: "tool",
  content: "",
  createdAt: new Date("2026-08-24T00:00:01Z"),
  toolCallId: "tc1",
  toolName: "execute_command",
  args: {},
  status: "streaming",
};

const pendingTool: DisplayMessage = {
  ...streamingTool,
  toolCallId: "tc2",
  toolName: "http_request",
  status: "pending",
};

const completedTool: DisplayMessage = {
  ...streamingTool,
  toolCallId: "tc3",
  toolName: "read_file",
  status: "completed",
};

// ---------------------------------------------------------------------------
// appendStreamedText
// ---------------------------------------------------------------------------

describe("appendStreamedText", () => {
  it("appends a new assistant message when the list ends with a user message", () => {
    const result = appendStreamedText([userMessage], "hello");

    expect(result).toHaveLength(2);
    expect(result[1]).toMatchObject({ role: "assistant", content: "hello" });
  });

  it("updates the trailing assistant message with the full accumulated text", () => {
    const assistant: DisplayMessage = {
      role: "assistant",
      content: "hel",
      createdAt: new Date("2026-08-24T00:00:02Z"),
    };
    const result = appendStreamedText([userMessage, assistant], "hello");

    expect(result).toHaveLength(2);
    expect(result[1]).toEqual({ ...assistant, content: "hello" });
  });

  it("starts a new assistant message after a tool message", () => {
    const result = appendStreamedText([userMessage, pendingTool], "next step");

    expect(result).toHaveLength(3);
    expect(result[2]).toMatchObject({
      role: "assistant",
      content: "next step",
    });
  });

  it("does not mutate the input list or trailing assistant message", () => {
    const assistant: DisplayMessage = {
      role: "assistant",
      content: "hel",
      createdAt: new Date("2026-08-24T00:00:02Z"),
    };
    const messages = [userMessage, assistant];
    const original = structuredClone(messages);

    const result = appendStreamedText(messages, "hello");

    expect(messages).toEqual(original);
    expect(result).not.toBe(messages);
    expect(result[1]).not.toBe(assistant);
  });
});

// ---------------------------------------------------------------------------
// startStreamingToolCall
// ---------------------------------------------------------------------------

describe("startStreamingToolCall", () => {
  it("appends a streaming tool message with empty args", () => {
    const result = startStreamingToolCall([userMessage], "tc1", "nmap");

    expect(result).toHaveLength(2);
    expect(result[1]).toMatchObject({
      role: "tool",
      toolCallId: "tc1",
      toolName: "nmap",
      args: {},
      status: "streaming",
    });
  });

  it("does not mutate the input list", () => {
    const messages = [userMessage];
    const original = structuredClone(messages);

    startStreamingToolCall(messages, "tc1", "nmap");

    expect(messages).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// applyToolCallDelta
// ---------------------------------------------------------------------------

describe("applyToolCallDelta", () => {
  it("updates args on the matching streaming tool message", () => {
    const parsed = { command: "nmap example.com" };
    const result = applyToolCallDelta(
      [userMessage, streamingTool],
      "tc1",
      parsed,
    );

    expect(result).toHaveLength(2);
    expect(result[1]).toMatchObject({ args: parsed });
  });

  it("derives logs from streamable content in the parsed args", () => {
    const parsed = { content: "line1\nline2" };
    const result = applyToolCallDelta(
      [userMessage, streamingTool],
      "tc1",
      parsed,
    );

    expect(result[1].logs).toEqual(["line1", "line2"]);
  });

  it("omits logs when the parsed args carry no streamable content", () => {
    const parsed = { path: "/etc/hosts" };
    const result = applyToolCallDelta(
      [userMessage, streamingTool],
      "tc1",
      parsed,
    );

    expect(result[1].args).toEqual(parsed);
    expect(result[1].logs).toBeUndefined();
  });

  it("returns the input unchanged when no tool message matches", () => {
    const messages = [userMessage, streamingTool];
    const result = applyToolCallDelta(messages, "unknown", { a: 1 });

    expect(result).toBe(messages);
  });

  it("does not mutate the input list", () => {
    const messages = [userMessage, streamingTool];
    const original = structuredClone(messages);

    applyToolCallDelta(messages, "tc1", { command: "ls" });

    expect(messages).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// applyToolCall
// ---------------------------------------------------------------------------

describe("applyToolCall", () => {
  it("transitions a streaming tool to pending with final args and clears logs", () => {
    const withLogs: DisplayMessage = { ...streamingTool, logs: ["partial"] };
    const args = { command: "nmap example.com" };
    const result = applyToolCall(
      [userMessage, withLogs],
      "tc1",
      "execute_command",
      args,
    );

    expect(result[1]).toMatchObject({
      toolCallId: "tc1",
      args,
      status: "pending",
      logs: undefined,
    });
  });

  it("appends a pending tool message when none exists", () => {
    const result = applyToolCall([userMessage], "tc9", "execute_command", {
      command: "ls",
    });

    expect(result).toHaveLength(2);
    expect(result[1]).toMatchObject({
      role: "tool",
      toolCallId: "tc9",
      toolName: "execute_command",
      args: { command: "ls" },
      status: "pending",
    });
  });

  it("does not mutate the input list", () => {
    const messages = [userMessage, streamingTool];
    const original = structuredClone(messages);

    applyToolCall(messages, "tc1", "execute_command", { command: "ls" });

    expect(messages).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// applyToolResult
// ---------------------------------------------------------------------------

describe("applyToolResult", () => {
  it("marks the matching tool completed with the result", () => {
    const result = applyToolResult([userMessage, pendingTool], "tc2", {
      out: 1,
    });

    expect(result[1]).toMatchObject({
      toolCallId: "tc2",
      status: "completed",
      result: { out: 1 },
    });
  });

  it("returns the input unchanged when no tool message matches", () => {
    const messages = [userMessage, pendingTool];
    const result = applyToolResult(messages, "unknown", null);

    expect(result).toBe(messages);
  });

  it("does not mutate the input list", () => {
    const messages = [userMessage, pendingTool];
    const original = structuredClone(messages);

    applyToolResult(messages, "tc2", "done");

    expect(messages).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// mergeCommandOutput
// ---------------------------------------------------------------------------

describe("mergeCommandOutput", () => {
  it("appends output lines to the last active tool message", () => {
    const messages = [userMessage, pendingTool, completedTool];
    const result = mergeCommandOutput(messages, "line1\nline2");

    expect(result[1].logs).toEqual(["line1", "line2"]);
    expect(result[2]).toBe(completedTool);
  });

  it("targets the most recent pending or streaming tool only", () => {
    const laterPending: DisplayMessage = {
      ...pendingTool,
      toolCallId: "tc4",
      createdAt: new Date("2026-08-24T00:00:05Z"),
    };
    const messages = [userMessage, streamingTool, laterPending];
    const result = mergeCommandOutput(messages, "hello");

    expect(result[1].logs).toBeUndefined();
    expect(result[2].logs).toEqual(["hello"]);
  });

  it("merges a trailing partial line with the first incoming line", () => {
    const withPartial: DisplayMessage = { ...pendingTool, logs: ["partial"] };
    const result = mergeCommandOutput([withPartial], " continued\nnext");

    expect(result[0].logs).toEqual(["partial continued", "next"]);
  });

  it("does not merge the last line when the buffer starts with a newline", () => {
    const withLine: DisplayMessage = { ...pendingTool, logs: ["complete"] };
    const result = mergeCommandOutput([withLine], "\nnext");

    expect(result[0].logs).toEqual(["complete", "", "next"]);
  });

  it("returns the input unchanged when no tool is active", () => {
    const messages = [userMessage, completedTool];
    const result = mergeCommandOutput(messages, "orphaned output");

    expect(result).toBe(messages);
  });

  it("caps retained logs at MAX_LOG_LINES, keeping the newest lines", () => {
    const bigLogs = Array.from({ length: MAX_LOG_LINES }, (_, i) => `old-${i}`);
    const withLogs: DisplayMessage = { ...pendingTool, logs: bigLogs };
    const result = mergeCommandOutput([withLogs], "new-0\nnew-1");

    // The last existing line was partial, so "new-0" merges into it; the cap
    // then trims the single oldest line.
    expect(result[0].logs).toHaveLength(MAX_LOG_LINES);
    expect(result[0].logs?.at(-2)).toBe("old-199new-0");
    expect(result[0].logs?.at(-1)).toBe("new-1");
    expect(result[0].logs?.[0]).toBe("old-1");
  });

  it("does not mutate the input list or existing logs array", () => {
    const withLogs: DisplayMessage = { ...pendingTool, logs: ["a"] };
    const messages = [withLogs];
    const original = structuredClone(messages);

    mergeCommandOutput(messages, "b");

    expect(messages).toEqual(original);
    expect(withLogs.logs).toEqual(["a"]);
  });
});
