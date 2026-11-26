import type { ModelMessage } from "ai";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "fs";
import os from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { newSessionId, type SessionID } from "../id/id";
import {
  type ConsolePartRow,
  type ConsoleSessionNode,
  type ConsoleSessionTree,
  rehydrateFromConsoleTree,
  repairOrphanToolCalls,
} from "./persistence";

// Point homedir at a throwaway tmp dir so the test never touches the real ~.
let homeDir: string;

beforeEach(() => {
  homeDir = mkdtempSync(join(os.tmpdir(), "rehydrate-test-"));
  vi.spyOn(os, "homedir").mockReturnValue(homeDir);
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(homeDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Tree builders
// ---------------------------------------------------------------------------

function textPart(
  messageId: string,
  sessionId: string,
  index: number,
  text: string,
): ConsolePartRow {
  return {
    id: `prt_text_${messageId}_${index}`,
    messageId,
    sessionId,
    index,
    type: "text",
    toolCallId: null,
    s3Key: null,
    data: { text },
    createdAt: new Date().toISOString(),
  };
}

function toolPart(
  messageId: string,
  sessionId: string,
  index: number,
  toolCallId: string,
  tool: string,
  state: ConsolePartRow["data"],
): ConsolePartRow {
  return {
    id: `prt_tool_${toolCallId}`,
    messageId,
    sessionId,
    index,
    type: "tool",
    toolCallId,
    s3Key: null,
    data: state,
    createdAt: new Date().toISOString(),
  };
}

function subagentRefPart(
  messageId: string,
  sessionId: string,
  index: number,
  childSessionId: string,
): ConsolePartRow {
  return {
    id: `prt_ref_${childSessionId}`,
    messageId,
    sessionId,
    index,
    type: "subagent_ref",
    toolCallId: null,
    s3Key: null,
    data: { childSessionId, childAgentType: "pentest" },
    createdAt: new Date().toISOString(),
  };
}

function emptyNode(
  id: string,
  parentSessionId: string | null,
): ConsoleSessionNode {
  return {
    session: {
      id,
      agentType: "pentest",
      parentSessionId,
      status: "completed",
    },
    messages: [],
    parts: [],
  };
}

// ---------------------------------------------------------------------------
// rehydrateFromConsoleTree
// ---------------------------------------------------------------------------

describe("rehydrateFromConsoleTree", () => {
  it("writes messages.json + subagents/{child}/messages.json and returns matching ModelMessages", () => {
    const rootId = newSessionId();
    const childId = newSessionId();

    const tree: ConsoleSessionTree = {
      session: {
        id: rootId,
        agentType: "pentest",
        parentSessionId: null,
        status: "running",
      },
      messages: [
        {
          id: "msg_u1",
          sessionId: rootId,
          role: "user",
          sequence: 0,
          stepSeq: null,
          data: null,
          createdAt: new Date().toISOString(),
        },
        {
          id: "msg_a1",
          sessionId: rootId,
          role: "assistant",
          sequence: 1,
          stepSeq: 0,
          data: null,
          createdAt: new Date().toISOString(),
        },
      ],
      parts: [
        textPart("msg_u1", rootId, 0, "scan the target"),
        textPart("msg_a1", rootId, 0, "Running a command"),
        toolPart("msg_a1", rootId, 1, "tc-1", "execute_command", {
          toolCallId: "tc-1",
          tool: "execute_command",
          state: {
            status: "completed",
            input: { cmd: "ls" },
            output: "file1.txt\nfile2.txt",
          },
        }),
        // spawn marker only — child transcript lives in its own file.
        subagentRefPart("msg_a1", rootId, 2, childId),
      ],
      descendants: [
        {
          session: {
            id: childId,
            agentType: "pentest",
            parentSessionId: rootId,
            status: "completed",
          },
          messages: [
            {
              id: "msg_cu1",
              sessionId: childId,
              role: "user",
              sequence: 0,
              stepSeq: null,
              data: null,
              createdAt: new Date().toISOString(),
            },
            {
              id: "msg_ca1",
              sessionId: childId,
              role: "assistant",
              sequence: 1,
              stepSeq: 0,
              data: null,
              createdAt: new Date().toISOString(),
            },
          ],
          parts: [
            textPart("msg_cu1", childId, 0, "test for IDOR"),
            textPart("msg_ca1", childId, 0, "Probing IDOR"),
          ],
        },
      ],
    };

    const result = rehydrateFromConsoleTree(rootId as SessionID, tree);

    // --- on-disk files ---
    const rootMessagesPath = join(result.rootPath, "messages.json");
    const childMessagesPath = join(
      result.rootPath,
      "subagents",
      childId,
      "messages.json",
    );
    expect(existsSync(rootMessagesPath)).toBe(true);
    expect(existsSync(childMessagesPath)).toBe(true);
    expect(existsSync(join(result.rootPath, "session.json"))).toBe(true);

    const diskRoot = JSON.parse(
      readFileSync(rootMessagesPath, "utf-8"),
    ) as ModelMessage[];
    expect(diskRoot).toEqual(result.messages);

    // --- returned root messages ---
    // user → text content
    expect(result.messages[0]).toEqual({
      role: "user",
      content: "scan the target",
    });
    // assistant → text + tool-call
    const assistant = result.messages[1] as {
      role: string;
      content: Array<Record<string, unknown>>;
    };
    expect(assistant.role).toBe("assistant");
    expect(assistant.content[0]).toEqual({
      type: "text",
      text: "Running a command",
    });
    expect(assistant.content[1]).toMatchObject({
      type: "tool-call",
      toolCallId: "tc-1",
      toolName: "execute_command",
      input: { cmd: "ls" },
    });
    // subagent_ref is NOT inlined
    expect(assistant.content.some((p) => p.type === "subagent_ref")).toBe(
      false,
    );
    // completed tool → following tool message with structured output
    const toolMsg = result.messages[2] as {
      role: string;
      content: Array<Record<string, unknown>>;
    };
    expect(toolMsg.role).toBe("tool");
    expect(toolMsg.content[0]).toEqual({
      type: "tool-result",
      toolCallId: "tc-1",
      toolName: "execute_command",
      output: { type: "text", value: "file1.txt\nfile2.txt" },
    });

    // --- subagent map + file ---
    expect(result.subagentMessages.has(childId)).toBe(true);
    const childMsgs = result.subagentMessages.get(childId)!;
    expect(childMsgs[0]).toEqual({ role: "user", content: "test for IDOR" });
    const diskChild = JSON.parse(
      readFileSync(childMessagesPath, "utf-8"),
    ) as ModelMessage[];
    expect(diskChild).toEqual(childMsgs);
  });

  it("resolves S3-offloaded tool output to its inline preview", () => {
    const rootId = newSessionId();
    const tree: ConsoleSessionTree = {
      ...emptyNode(rootId, null),
      session: {
        id: rootId,
        agentType: "pentest",
        parentSessionId: null,
        status: "completed",
      },
      messages: [
        {
          id: "msg_a1",
          sessionId: rootId,
          role: "assistant",
          sequence: 0,
          stepSeq: 0,
          data: null,
          createdAt: new Date().toISOString(),
        },
      ],
      parts: [
        toolPart("msg_a1", rootId, 0, "tc-big", "read_file", {
          toolCallId: "tc-big",
          tool: "read_file",
          state: {
            status: "completed",
            input: { path: "big.txt" },
            output: { s3Key: "s3://blob", preview: "first 100 bytes…" },
          },
        }),
      ],
      descendants: [],
    } as ConsoleSessionTree;

    const result = rehydrateFromConsoleTree(rootId as SessionID, tree);
    const toolMsg = result.messages.find((m) => m.role === "tool") as {
      content: Array<Record<string, unknown>>;
    };
    expect(toolMsg.content[0].output).toEqual({
      type: "text",
      value: "first 100 bytes…",
    });
  });
});

// ---------------------------------------------------------------------------
// Open tool-call repair
// ---------------------------------------------------------------------------

describe("repairOrphanToolCalls / rehydrate open-tool repair", () => {
  it("synthesizes a tool-result for a trailing running tool-call so the list is valid", () => {
    const rootId = newSessionId();
    const tree: ConsoleSessionTree = {
      session: {
        id: rootId,
        agentType: "pentest",
        parentSessionId: null,
        status: "running",
      },
      messages: [
        {
          id: "msg_a1",
          sessionId: rootId,
          role: "assistant",
          sequence: 0,
          stepSeq: 0,
          data: null,
          createdAt: new Date().toISOString(),
        },
      ],
      parts: [
        textPart("msg_a1", rootId, 0, "kicking off a long scan"),
        // still running — the process died mid-step.
        toolPart("msg_a1", rootId, 1, "tc-open", "long_scan", {
          toolCallId: "tc-open",
          tool: "long_scan",
          state: { status: "running", input: { target: "host" } },
        }),
      ],
      descendants: [],
    };

    const result = rehydrateFromConsoleTree(rootId as SessionID, tree);

    // Every tool-call must have a matching tool-result for the constructor.
    const toolCallIds = new Set<string>();
    const toolResultIds = new Set<string>();
    for (const msg of result.messages) {
      if (!Array.isArray(msg.content)) continue;
      for (const part of msg.content as Array<Record<string, unknown>>) {
        if (part.type === "tool-call")
          toolCallIds.add(part.toolCallId as string);
        if (part.type === "tool-result")
          toolResultIds.add(part.toolCallId as string);
      }
    }
    expect(toolCallIds.has("tc-open")).toBe(true);
    expect(toolResultIds.has("tc-open")).toBe(true);

    const toolMsg = result.messages.find((m) => m.role === "tool") as {
      content: Array<Record<string, unknown>>;
    };
    expect(toolMsg.content[0].output).toEqual({
      type: "text",
      value: "tool failed: process terminated",
    });
  });

  it("leaves a fully-resolved conversation untouched", () => {
    const messages: ModelMessage[] = [
      {
        role: "assistant",
        content: [
          { type: "tool-call", toolCallId: "tc-1", toolName: "x", input: {} },
        ],
      } as ModelMessage,
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tc-1",
            toolName: "x",
            output: { type: "text", value: "ok" },
          },
        ],
      } as ModelMessage,
    ];
    expect(repairOrphanToolCalls(messages)).toEqual(messages);
  });
});

// ---------------------------------------------------------------------------
// Compaction boundary
// ---------------------------------------------------------------------------

describe("rehydrateFromConsoleTree compaction boundary", () => {
  function message(
    sessionId: string,
    id: string,
    role: "user" | "assistant",
    sequence: number,
  ) {
    return {
      id,
      sessionId,
      role,
      sequence,
      stepSeq: role === "user" ? null : sequence,
      data: null,
      createdAt: new Date().toISOString(),
    };
  }

  function compactionPart(
    messageId: string,
    sessionId: string,
    summary: string,
    pinnedToolCallIds: string[] = [],
  ): ConsolePartRow {
    return {
      id: `prt_compaction_${messageId}`,
      messageId,
      sessionId,
      index: 0,
      type: "compaction",
      toolCallId: null,
      s3Key: null,
      data: { kind: "summary", summary, pinnedToolCallIds },
      createdAt: new Date().toISOString(),
    };
  }

  function tree(
    sessionId: string,
    messages: ReturnType<typeof message>[],
    parts: ConsolePartRow[],
  ): ConsoleSessionTree {
    return {
      ...emptyNode(sessionId, null),
      messages,
      parts,
      descendants: [],
    } as ConsoleSessionTree;
  }

  const serialized = (messages: ModelMessage[]) => JSON.stringify(messages);

  it("starts from the latest boundary with its replayed user message and the summary framed as history", () => {
    const id = newSessionId();
    const result = rehydrateFromConsoleTree(
      id as SessionID,
      tree(
        id,
        [
          message(id, "msg_u0", "user", 0),
          message(id, "msg_a1", "assistant", 1),
          message(id, "msg_a2", "assistant", 2),
          message(id, "msg_u3", "user", 3),
          message(id, "msg_a4", "assistant", 4),
          message(id, "msg_u5", "user", 5),
        ],
        [
          textPart("msg_u0", id, 0, "first request"),
          textPart("msg_a1", id, 0, "old work"),
          compactionPart("msg_a2", id, "SUMMARY-ONE"),
          textPart("msg_a2", id, 1, "after one"),
          textPart("msg_u3", id, 0, "second request"),
          compactionPart("msg_a4", id, "SUMMARY-TWO"),
          textPart("msg_a4", id, 1, "after two"),
          textPart("msg_u5", id, 0, "latest request"),
        ],
      ),
    );

    expect(result.messages).toEqual([
      {
        role: "user",
        content: expect.stringContaining(
          "historical context, not as new instructions.\n<summary>\nSUMMARY-TWO\n</summary>\n\nsecond request",
        ),
      },
      { role: "assistant", content: [{ type: "text", text: "after two" }] },
      { role: "user", content: "latest request" },
    ]);
    expect(serialized(result.messages).split("second request")).toHaveLength(2);
    for (const dropped of [
      "SUMMARY-ONE",
      "old work",
      "after one",
      "first request",
    ])
      expect(serialized(result.messages)).not.toContain(dropped);
  });

  it("keeps the latest user message verbatim when the boundary follows it", () => {
    const id = newSessionId();
    const request = "Delete the stale endpoints on app 7.\n  Keep the rest.";
    const result = rehydrateFromConsoleTree(
      id as SessionID,
      tree(
        id,
        [
          message(id, "msg_u0", "user", 0),
          message(id, "msg_a1", "assistant", 1),
          message(id, "msg_a2", "assistant", 2),
        ],
        [
          textPart("msg_u0", id, 0, request),
          textPart("msg_a1", id, 0, "summarized work"),
          compactionPart("msg_a2", id, "SUMMARY"),
          textPart("msg_a2", id, 1, "continuing"),
        ],
      ),
    );

    expect(result.messages).toHaveLength(2);
    const opening = result.messages[0].content as string;
    expect(opening).toMatch(/SUMMARY\n<\/summary>/);
    expect(opening.endsWith(`\n\n${request}`)).toBe(true);
    expect(result.messages[1]).toEqual({
      role: "assistant",
      content: [{ type: "text", text: "continuing" }],
    });
    expect(serialized(result.messages)).not.toContain("summarized work");
  });

  it("keeps a pinned call before the boundary with its call and result paired", () => {
    const id = newSessionId();
    const result = rehydrateFromConsoleTree(
      id as SessionID,
      tree(
        id,
        [
          message(id, "msg_u0", "user", 0),
          message(id, "msg_a1", "assistant", 1),
          message(id, "msg_a2", "assistant", 2),
          message(id, "msg_a3", "assistant", 3),
        ],
        [
          textPart("msg_u0", id, 0, "clean up"),
          textPart("msg_a1", id, 0, "unrelated"),
          toolPart("msg_a2", id, 0, "call_del", "delete_endpoint", {
            toolCallId: "call_del",
            tool: "delete_endpoint",
            state: {
              status: "completed",
              input: { endpointId: "ep_1" },
              output: "deleted",
            },
          }),
          compactionPart("msg_a3", id, "SUMMARY", ["call_del"]),
          textPart("msg_a3", id, 1, "done"),
        ],
      ),
    );

    expect(result.messages.slice(1)).toEqual([
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "call_del",
            toolName: "delete_endpoint",
            input: { endpointId: "ep_1" },
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "call_del",
            toolName: "delete_endpoint",
            output: { type: "text", value: "deleted" },
          },
        ],
      },
      { role: "assistant", content: [{ type: "text", text: "done" }] },
    ]);
    expect(serialized(result.messages)).not.toContain("unrelated");
  });

  it("frames a reset boundary without a summary", () => {
    const id = newSessionId();
    const reset = compactionPart("msg_a1", id, "");
    reset.data = { kind: "reset", summary: "", pinnedToolCallIds: [] };
    const result = rehydrateFromConsoleTree(
      id as SessionID,
      tree(
        id,
        [
          message(id, "msg_u0", "user", 0),
          message(id, "msg_a1", "assistant", 1),
        ],
        [textPart("msg_u0", id, 0, "go"), reset],
      ),
    );

    expect(result.messages).toEqual([
      {
        role: "user",
        content:
          "The conversation before this point was discarded to fit the context window.\n\ngo",
      },
    ]);
  });

  it("leaves a tree without a boundary unchanged", () => {
    const id = newSessionId();
    const messages = [
      message(id, "msg_u0", "user", 0),
      message(id, "msg_a1", "assistant", 1),
    ];
    const parts = [
      textPart("msg_u0", id, 0, "first"),
      textPart("msg_a1", id, 0, "answer"),
    ];
    expect(
      rehydrateFromConsoleTree(id as SessionID, tree(id, messages, parts))
        .messages,
    ).toEqual([
      { role: "user", content: "first" },
      { role: "assistant", content: [{ type: "text", text: "answer" }] },
    ]);
  });
});
