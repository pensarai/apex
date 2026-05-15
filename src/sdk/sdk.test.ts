import { describe, expect, it } from "vitest";
import {
  isEventID,
  isMessageID,
  isNodeID,
  isPartID,
  isSessionID,
  mintEventID,
  mintMessageID,
  mintNodeID,
  mintPartID,
  mintSessionID,
} from "./ids.ts";
import {
  type ApexMessage,
  ApexMessageSchema,
  isDurableMessage,
} from "./messages.ts";
import { SequenceCounter } from "./sequence.ts";
import { Session } from "./session.ts";
import { createRun } from "./stream.ts";
import { Subagent } from "./subagent.ts";

describe("sdk/ids", () => {
  it("mints IDs with correct branded prefixes", () => {
    expect(isSessionID(mintSessionID())).toBe(true);
    expect(isNodeID(mintNodeID())).toBe(true);
    expect(isMessageID(mintMessageID())).toBe(true);
    expect(isPartID(mintPartID())).toBe(true);
    expect(isEventID(mintEventID())).toBe(true);
  });

  it("mint helpers return unique IDs on each call", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) ids.add(mintNodeID());
    expect(ids.size).toBe(100);
  });
});

describe("sdk/sequence", () => {
  it("returns monotonically increasing values per session", () => {
    const counter = new SequenceCounter();
    const a = mintSessionID();
    const b = mintSessionID();
    expect(counter.next(a)).toBe(1);
    expect(counter.next(a)).toBe(2);
    expect(counter.next(b)).toBe(1); // independent per session
    expect(counter.next(a)).toBe(3);
  });

  it("peek does not advance, restore overrides", () => {
    const counter = new SequenceCounter();
    const id = mintSessionID();
    counter.next(id);
    counter.next(id);
    expect(counter.peek(id)).toBe(2);
    counter.restore(id, 42);
    expect(counter.next(id)).toBe(43);
  });
});

describe("sdk/session", () => {
  it("mints a fresh ID when none provided", () => {
    const s = new Session();
    expect(isSessionID(s.id)).toBe(true);
  });

  it("nextSequence is monotonic", () => {
    const s = new Session();
    expect(s.nextSequence()).toBe(1);
    expect(s.nextSequence()).toBe(2);
  });

  it("preserves parent session and scope", () => {
    const parent = mintSessionID();
    const s = new Session({
      parentSessionId: parent,
      scope: "recon_job",
      label: "child",
    });
    expect(s.parentSessionId).toBe(parent);
    expect(s.scope).toBe("recon_job");
    expect(s.label).toBe("child");
  });
});

describe("sdk/messages — Zod roundtrip per variant", () => {
  const sid = mintSessionID();
  const nid = mintNodeID();
  const mid = mintMessageID();
  const pid = mintPartID();
  const now = new Date().toISOString();

  const variants: ApexMessage[] = [
    {
      type: "node.created",
      node: {
        id: nid,
        sessionId: sid,
        parentId: null,
        parentToolCallId: null,
        sequence: 1,
        kind: "agent",
        state: "running",
        name: "root",
        payload: {},
        createdAt: now,
      },
      sequence: 1,
      timestamp: now,
    },
    {
      type: "node.state",
      nodeId: nid,
      state: "completed",
      reason: "ok",
      sequence: 2,
      timestamp: now,
    },
    {
      type: "node.completed",
      nodeId: nid,
      result: { foo: "bar" },
      sequence: 3,
      timestamp: now,
    },
    {
      type: "message.created",
      message: {
        id: mid,
        nodeId: nid,
        sessionId: sid,
        role: "assistant",
        sequence: 1,
        createdAt: now,
      },
      parts: [
        {
          id: pid,
          type: "text",
          messageId: mid,
          sequence: 0,
          content: { text: "hello" },
        },
      ],
      sequence: 4,
      timestamp: now,
    },
    {
      type: "part.added",
      part: {
        id: pid,
        type: "tool-call",
        messageId: mid,
        sequence: 1,
        content: { toolCallId: "tc_1", toolName: "search", args: { q: "x" } },
      },
      sequence: 5,
      timestamp: now,
    },
    {
      type: "part.updated",
      partId: pid,
      messageId: mid,
      patch: { content: { text: "updated" } },
      sequence: 6,
      timestamp: now,
    },
    {
      type: "usage.recorded",
      nodeId: nid,
      model: "claude-opus-4-7",
      tokens: { inputTokens: 100, outputTokens: 50 },
      cost: 0.0042,
      sequence: 7,
      timestamp: now,
    },
    {
      type: "step.finished",
      nodeId: nid,
      finishReason: "stop",
      sequence: 8,
      timestamp: now,
    },
    {
      type: "text.delta",
      messageId: mid,
      partId: pid,
      delta: " world",
    },
    {
      type: "tool.input.delta",
      nodeId: nid,
      argsTextDelta: '{"q"',
    },
    {
      type: "command.output",
      nodeId: nid,
      data: "stdout chunk",
    },
    {
      type: "error",
      nodeId: nid,
      error: { message: "boom", details: { code: 1 } },
    },
    {
      type: "done",
      sessionId: sid,
      result: "ok",
    },
  ];

  it.each(variants)("parses %s", (variant) => {
    const parsed = ApexMessageSchema.parse(variant);
    expect(parsed.type).toBe(variant.type);
  });

  it("classifies durable vs transient correctly", () => {
    const durable = [
      "node.created",
      "node.state",
      "node.completed",
      "message.created",
      "part.added",
      "part.updated",
      "usage.recorded",
      "step.finished",
    ];
    const transient = [
      "text.delta",
      "tool.input.delta",
      "command.output",
      "error",
      "done",
    ];
    for (const variant of variants) {
      const shouldBeDurable = durable.includes(variant.type);
      const shouldBeTransient = transient.includes(variant.type);
      expect(isDurableMessage(variant)).toBe(
        shouldBeDurable && !shouldBeTransient,
      );
    }
  });
});

describe("sdk/stream — createRun", () => {
  it("delivers messages and resolves with result", async () => {
    const sid = mintSessionID();
    const run = createRun(sid, async (emit) => {
      emit({
        type: "text.delta",
        messageId: mintMessageID(),
        partId: mintPartID(),
        delta: "hi",
      });
      emit({ type: "done", sessionId: sid, result: "ok" });
      return "ok";
    });

    const seen: ApexMessage["type"][] = [];
    for await (const msg of run) seen.push(msg.type);
    await expect(run.result()).resolves.toBe("ok");
    expect(seen).toEqual(["text.delta", "done"]);
  });

  it("abort stops iteration and rejects result", async () => {
    const sid = mintSessionID();
    const run = createRun(sid, async (_emit, signal) => {
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
      return "unreachable";
    });

    run.abort(new Error("user cancelled"));
    await expect(run.result()).rejects.toBeDefined();
  });
});

describe("sdk/subagent — Subagent.spawn", () => {
  it("emits node.created with parent linkage and node.completed on success", async () => {
    const session = new Session();
    const parentNodeId = mintNodeID();
    const emitted: ApexMessage[] = [];

    const handle = Subagent.spawn(
      {
        session,
        parentNodeId,
        parentToolCallId: "tc_root",
        kind: "agent",
        name: "child",
      },
      (msg) => emitted.push(msg),
      async ({ nodeId, emit }) => {
        emit({
          type: "text.delta",
          messageId: mintMessageID(),
          partId: mintPartID(),
          delta: `from ${nodeId}`,
        });
        return { ok: true };
      },
    );

    await expect(handle.promise).resolves.toEqual({ ok: true });

    const created = emitted.find((m) => m.type === "node.created");
    const completed = emitted.find((m) => m.type === "node.completed");
    expect(created).toBeDefined();
    expect(completed).toBeDefined();
    if (created && created.type === "node.created") {
      expect(created.node.parentId).toBe(parentNodeId);
      expect(created.node.parentToolCallId).toBe("tc_root");
    }
    if (completed && completed.type === "node.completed") {
      expect(completed.result).toEqual({ ok: true });
    }
  });

  it("emits node.completed with errorMessage on failure", async () => {
    const session = new Session();
    const emitted: ApexMessage[] = [];

    const handle = Subagent.spawn(
      { session, parentNodeId: mintNodeID() },
      (msg) => emitted.push(msg),
      async () => {
        throw new Error("kaboom");
      },
    );

    await expect(handle.promise).rejects.toThrow("kaboom");
    const completed = emitted.find((m) => m.type === "node.completed");
    expect(completed).toBeDefined();
    if (completed && completed.type === "node.completed") {
      expect(completed.errorMessage).toBe("kaboom");
    }
  });
});
