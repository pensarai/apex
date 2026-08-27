import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DisplayMessage } from "../agent-display";
import {
  recoverAbortedConversation,
  recoverAbortedTranscript,
  rewriteToolResultOutput,
} from "./conversation";

// ---------------------------------------------------------------------------
// recoverAbortedConversation
// ---------------------------------------------------------------------------

describe("recoverAbortedConversation", () => {
  const userConversation: ModelMessage[] = [
    {
      role: "user",
      content: [{ type: "text", text: "scan the target" }],
    },
  ];

  it("does not recover a conversation that already has an assistant response", () => {
    const conversation: ModelMessage[] = [
      ...userConversation,
      {
        role: "assistant",
        content: [{ type: "text", text: "Scan complete" }],
      },
    ];
    const original = structuredClone(conversation);

    expect(recoverAbortedConversation(conversation, "partial", [])).toBeNull();
    expect(conversation).toEqual(original);
  });

  it("appends the interruption placeholder when no response was streamed", () => {
    const recovered = recoverAbortedConversation(userConversation, "  \n ", []);

    expect(recovered).toEqual([
      ...userConversation,
      {
        role: "assistant",
        content: [{ type: "text", text: "[Response interrupted by user.]" }],
      },
    ]);
  });

  it("trims and preserves a partial assistant response", () => {
    const recovered = recoverAbortedConversation(
      userConversation,
      "  partial response\n",
      [],
    );

    expect(recovered?.at(-1)).toEqual({
      role: "assistant",
      content: [{ type: "text", text: "partial response" }],
    });
  });

  it("pairs pending tools and ignores settled display messages", () => {
    const createdAt = new Date("2026-08-24T00:00:00Z");
    const displayMessages: DisplayMessage[] = [
      {
        role: "assistant",
        content: "Working",
        createdAt,
      },
      {
        role: "tool",
        content: "",
        createdAt,
        toolCallId: "pending-tool",
        toolName: "execute_command",
        args: { command: "nmap example.com" },
        status: "pending",
      },
      {
        role: "tool",
        content: "",
        createdAt,
        toolCallId: "streaming-tool",
        toolName: "http_request",
        status: "streaming",
      },
      {
        role: "tool",
        content: "",
        createdAt,
        toolCallId: "completed-tool",
        toolName: "read_file",
        args: { path: "notes.txt" },
        status: "completed",
      },
      {
        role: "tool",
        content: "",
        createdAt,
        toolCallId: "failed-tool",
        toolName: "glob",
        args: { pattern: "*.ts" },
        status: "error",
      },
    ];
    const originalConversation = structuredClone(userConversation);
    const originalDisplayMessages = structuredClone(displayMessages);

    const recovered = recoverAbortedConversation(
      userConversation,
      "Checking tools",
      displayMessages,
    );

    expect(recovered).toEqual([
      ...userConversation,
      {
        role: "assistant",
        content: [
          { type: "text", text: "Checking tools" },
          {
            type: "tool-call",
            toolCallId: "pending-tool",
            toolName: "execute_command",
            input: { command: "nmap example.com" },
          },
          {
            type: "tool-call",
            toolCallId: "streaming-tool",
            toolName: "http_request",
            input: {},
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "pending-tool",
            toolName: "execute_command",
            output: { type: "text", value: "Cancelled by user." },
          },
          {
            type: "tool-result",
            toolCallId: "streaming-tool",
            toolName: "http_request",
            output: { type: "text", value: "Cancelled by user." },
          },
        ],
      },
    ]);
    expect(recovered).not.toBe(userConversation);
    expect(userConversation).toEqual(originalConversation);
    expect(displayMessages).toEqual(originalDisplayMessages);
  });
});

// ---------------------------------------------------------------------------
// rewriteToolResultOutput
// ---------------------------------------------------------------------------

describe("rewriteToolResultOutput", () => {
  const toolConversation: ModelMessage[] = [
    {
      role: "user",
      content: [{ type: "text", text: "run the scan" }],
    },
    {
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolCallId: "q1",
          toolName: "ask_user_questions",
          input: { questions: [] },
        },
      ],
    } as ModelMessage,
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "q1",
          toolName: "ask_user_questions",
          output: { type: "text", value: "pending" },
        },
      ],
    } as ModelMessage,
  ];

  it("replaces the matching tool-result output with the json wrapper", () => {
    const result = rewriteToolResultOutput(toolConversation, "q1", {
      answers: [],
      skipped: true,
    });

    const toolMsg = result.at(-1);
    expect(toolMsg?.role).toBe("tool");
    const part = (toolMsg?.content as Array<Record<string, unknown>>)[0];
    expect(part.output).toEqual({
      type: "json",
      value: { answers: [], skipped: true },
    });
  });

  it("returns the identical reference when no tool-result matches", () => {
    const result = rewriteToolResultOutput(toolConversation, "missing", {
      answers: [],
    });

    expect(result).toBe(toolConversation);
  });

  it("only rewrites the matching toolCallId, leaving other parts intact", () => {
    const multi: ModelMessage[] = [
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "a",
            toolName: "t",
            output: { type: "text", value: "keep-a" },
          },
          {
            type: "tool-result",
            toolCallId: "b",
            toolName: "t",
            output: { type: "text", value: "keep-b" },
          },
        ],
      } as ModelMessage,
    ];

    const result = rewriteToolResultOutput(multi, "b", { v: 1 });
    const parts = result[0].content as Array<{
      toolCallId: string;
      output: unknown;
    }>;

    expect(parts[0]).toMatchObject({
      toolCallId: "a",
      output: { type: "text", value: "keep-a" },
    });
    expect(parts[1].output).toEqual({ type: "json", value: { v: 1 } });
  });

  it("does not mutate the input conversation", () => {
    const original = structuredClone(toolConversation);

    rewriteToolResultOutput(toolConversation, "q1", { answers: [] });

    expect(toolConversation).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// recoverAbortedTranscript
// ---------------------------------------------------------------------------

describe("recoverAbortedTranscript", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "abort-transcript-test-"));
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  const messagesPath = () => join(rootPath, "messages.json");

  function readDisk(): unknown {
    return JSON.parse(readFileSync(messagesPath(), "utf-8"));
  }

  function writeDisk(value: unknown): void {
    writeFileSync(messagesPath(), JSON.stringify(value, null, 2), "utf-8");
  }

  const userMessage: ModelMessage = {
    role: "user",
    content: [{ type: "text", text: "scan the target" }],
  };

  const pendingTool: DisplayMessage = {
    role: "tool",
    content: "",
    createdAt: new Date("2026-08-25T00:00:00Z"),
    toolCallId: "tc-1",
    toolName: "execute_command",
    args: { command: "nmap example.com" },
    status: "pending",
  };

  it("missing file: recovers from the in-memory conversation and persists it", () => {
    const result = recoverAbortedTranscript({
      rootPath,
      conversation: [userMessage],
      partialText: "partial",
      displayMessages: [],
    });

    expect(result).toHaveLength(2);
    expect(result[1]).toMatchObject({ role: "assistant" });
    // The recovered transcript is written even though no file existed before.
    expect(readDisk()).toEqual(result);
  });

  it("missing file with nothing to recover: returns the input, writes nothing", () => {
    const conversation: ModelMessage[] = [
      userMessage,
      { role: "assistant", content: [{ type: "text", text: "done" }] },
    ];

    const result = recoverAbortedTranscript({
      rootPath,
      conversation,
      partialText: "",
      displayMessages: [],
    });

    expect(result).toBe(conversation);
    expect(existsSync(messagesPath())).toBe(false);
  });

  it("malformed file: keeps the in-memory conversation and leaves the file alone", () => {
    writeFileSync(messagesPath(), "{ not json", "utf-8");
    const conversation: ModelMessage[] = [userMessage];

    const result = recoverAbortedTranscript({
      rootPath,
      conversation,
      partialText: "partial",
      displayMessages: [],
    });

    // Read failed → no recovery attempted → input returned unchanged.
    expect(result).toBe(conversation);
    expect(readFileSync(messagesPath(), "utf-8")).toBe("{ not json");
  });

  it("empty transcript on disk: falls back to the in-memory conversation", () => {
    writeDisk([]);
    const conversation: ModelMessage[] = [userMessage];

    const result = recoverAbortedTranscript({
      rootPath,
      conversation,
      partialText: "partial",
      displayMessages: [],
    });

    // The empty persisted transcript must not clobber the in-memory base.
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual(userMessage);
  });

  it("already-complete transcript: reloads it and writes nothing", () => {
    const persisted: ModelMessage[] = [
      userMessage,
      { role: "assistant", content: [{ type: "text", text: "done" }] },
    ];
    writeDisk(persisted);

    const result = recoverAbortedTranscript({
      rootPath,
      conversation: [],
      partialText: "ignored",
      displayMessages: [pendingTool],
    });

    // Recovery gated off (transcript ends in an assistant turn) → the
    // reloaded transcript is returned and the file is left byte-identical.
    expect(result).toEqual(persisted);
    expect(readDisk()).toEqual(persisted);
  });

  it("partial text: recovers a trimmed assistant turn and persists it", () => {
    writeDisk([userMessage]);

    const result = recoverAbortedTranscript({
      rootPath,
      conversation: [],
      partialText: "  partial response\n",
      displayMessages: [],
    });

    expect(result[1]).toEqual({
      role: "assistant",
      content: [{ type: "text", text: "partial response" }],
    });
    expect(readDisk()).toEqual(result);
  });

  it("pending tool: pairs the cancelled tool-call/result and persists it", () => {
    writeDisk([userMessage]);

    const result = recoverAbortedTranscript({
      rootPath,
      conversation: [],
      partialText: "working",
      displayMessages: [pendingTool],
    });

    expect(result).toHaveLength(3);
    const assistant = result[1] as { content: Array<Record<string, unknown>> };
    expect(assistant.content[1]).toMatchObject({
      type: "tool-call",
      toolCallId: "tc-1",
    });
    const tool = result[2] as { content: Array<Record<string, unknown>> };
    expect(tool.content[0]).toMatchObject({
      type: "tool-result",
      toolCallId: "tc-1",
      output: { type: "text", value: "Cancelled by user." },
    });
    expect(readDisk()).toEqual(result);
  });
});
