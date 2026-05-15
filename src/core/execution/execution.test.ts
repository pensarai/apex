import { describe, expect, it } from "vitest";
import {
  AgentExecutionEventSchema,
  AgentNodeUnionSchema,
  DurableAgentEventSchema,
  ExecutionSessionSchema,
  isDurable,
  isTransient,
  MessageSchema,
  newEventId,
  newMessageId,
  newNodeId,
  newPartId,
  newSessionId,
  PartSchema,
  SequenceCounter,
  TransientAgentEventSchema,
  type AgentExecutionEvent,
  type SessionID,
} from "./index";

const NOW = () => new Date().toISOString();

describe("execution/ids — branded ID minting", () => {
  it("mints session IDs with ses_ prefix", () => {
    expect(newSessionId().startsWith("ses_")).toBe(true);
  });

  it("mints node IDs with nod_ prefix", () => {
    expect(newNodeId().startsWith("nod_")).toBe(true);
  });

  it("mints message IDs with msg_ prefix", () => {
    expect(newMessageId().startsWith("msg_")).toBe(true);
  });

  it("mints part IDs with prt_ prefix", () => {
    expect(newPartId().startsWith("prt_")).toBe(true);
  });

  it("mints event IDs with evt_ prefix", () => {
    expect(newEventId().startsWith("evt_")).toBe(true);
  });

  it("never collides across rapid successive mints", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) ids.add(newNodeId());
    expect(ids.size).toBe(1000);
  });
});

describe("execution/nodes — discriminated union", () => {
  const baseFields = {
    sessionId: newSessionId(),
    parentId: null,
    parentToolCallId: null,
    name: "test",
    state: "running" as const,
    sequence: 0,
    timeStarted: NOW(),
    timeCompleted: null,
  };

  it("accepts an agent node", () => {
    const result = AgentNodeUnionSchema.safeParse({
      id: newNodeId(),
      ...baseFields,
      kind: "agent",
      payload: { role: "offensive-security" },
    });
    expect(result.success).toBe(true);
  });

  it("accepts a workflow node", () => {
    const result = AgentNodeUnionSchema.safeParse({
      id: newNodeId(),
      ...baseFields,
      kind: "workflow",
      payload: { workflow: "whitebox-attack-surface" },
    });
    expect(result.success).toBe(true);
  });

  it("accepts a tool_call node", () => {
    const result = AgentNodeUnionSchema.safeParse({
      id: newNodeId(),
      ...baseFields,
      kind: "tool_call",
      payload: { toolName: "read_file", externalToolCallId: "tc_xyz" },
    });
    expect(result.success).toBe(true);
  });

  it("rejects an unknown kind", () => {
    const result = AgentNodeUnionSchema.safeParse({
      id: newNodeId(),
      ...baseFields,
      kind: "ghost",
      payload: {},
    });
    expect(result.success).toBe(false);
  });

  it("rejects an ID without the nod_ prefix", () => {
    const result = AgentNodeUnionSchema.safeParse({
      id: "not_a_node_id",
      ...baseFields,
      kind: "agent",
      payload: {},
    });
    expect(result.success).toBe(false);
  });
});

describe("execution/parts — discriminated union", () => {
  const baseFields = {
    sessionId: newSessionId(),
    messageId: newMessageId(),
    index: 0,
  };

  it("accepts every defined part type", () => {
    const parts = [
      { type: "text" as const, text: "hi" },
      { type: "reasoning" as const, text: "thinking" },
      { type: "file" as const, mimeType: "image/png", s3Key: "x" },
      {
        type: "tool" as const,
        toolName: "run",
        nodeId: newNodeId(),
        state: "running" as const,
      },
      { type: "step-start" as const },
      { type: "step-finish" as const },
      { type: "snapshot" as const },
      { type: "patch" as const, filePath: "a.ts", diff: "@@" },
      { type: "agent" as const, childNodeId: newNodeId() },
      { type: "subtask" as const, description: "do x" },
      { type: "retry" as const, attempt: 2 },
      {
        type: "compaction" as const,
        messagesCompacted: 5,
        summary: "summary",
      },
    ];
    for (const p of parts) {
      const result = PartSchema.safeParse({
        id: newPartId(),
        ...baseFields,
        ...p,
      });
      expect(result.success, `part ${p.type} should validate`).toBe(true);
    }
  });

  it("rejects unknown part type", () => {
    const result = PartSchema.safeParse({
      id: newPartId(),
      ...baseFields,
      type: "ghost-part",
    });
    expect(result.success).toBe(false);
  });
});

describe("execution/messages — schema", () => {
  it("accepts a valid assistant message", () => {
    const result = MessageSchema.safeParse({
      id: newMessageId(),
      sessionId: newSessionId(),
      nodeId: newNodeId(),
      role: "assistant",
      timeCreated: NOW(),
      metadata: { model: "claude-sonnet-4-6", tokensInput: 100 },
    });
    expect(result.success).toBe(true);
  });

  it("rejects an invalid role", () => {
    const result = MessageSchema.safeParse({
      id: newMessageId(),
      sessionId: newSessionId(),
      nodeId: newNodeId(),
      role: "robot",
      timeCreated: NOW(),
    });
    expect(result.success).toBe(false);
  });
});

describe("execution/sessions — schema", () => {
  it("accepts a fully-populated session", () => {
    const result = ExecutionSessionSchema.safeParse({
      id: newSessionId(),
      workspaceId: "ws_123",
      projectId: "proj_456",
      scope: "scan",
      title: "Scan #42",
      agent: "offensive-security",
      model: "claude-sonnet-4-6",
      status: "running",
      timeCreated: NOW(),
      timeUpdated: NOW(),
      timeCompleted: null,
      cost: 0.42,
      tokensInput: 100,
      tokensOutput: 50,
      tokensReasoning: null,
      tokensCacheRead: null,
      tokensCacheWrite: null,
      revert: null,
    });
    expect(result.success).toBe(true);
  });

  it("rejects an invalid scope", () => {
    const result = ExecutionSessionSchema.safeParse({
      id: newSessionId(),
      workspaceId: null,
      projectId: null,
      scope: "spaceship",
      title: null,
      agent: null,
      model: null,
      status: "pending",
      timeCreated: NOW(),
      timeUpdated: NOW(),
      timeCompleted: null,
      cost: null,
      tokensInput: null,
      tokensOutput: null,
      tokensReasoning: null,
      tokensCacheRead: null,
      tokensCacheWrite: null,
      revert: null,
    });
    expect(result.success).toBe(false);
  });
});

describe("execution/events — durable and transient", () => {
  const sessionId = newSessionId();
  const nodeId = newNodeId();

  const baseEvent = {
    id: newEventId(),
    sessionId,
    sequence: 0,
    emitterNodeId: nodeId,
    timestamp: NOW(),
  };

  it("accepts node.created as durable", () => {
    const result = DurableAgentEventSchema.safeParse({
      ...baseEvent,
      type: "node.created",
      channel: "durable",
      node: {
        id: nodeId,
        sessionId,
        parentId: null,
        parentToolCallId: null,
        name: "root",
        state: "running",
        sequence: 0,
        timeStarted: NOW(),
        timeCompleted: null,
        kind: "agent",
        payload: { role: "offensive-security" },
      },
    });
    expect(result.success).toBe(true);
  });

  it("accepts text.delta as transient", () => {
    const result = TransientAgentEventSchema.safeParse({
      ...baseEvent,
      type: "text.delta",
      channel: "transient",
      messageId: newMessageId(),
      partId: newPartId(),
      delta: "hello",
    });
    expect(result.success).toBe(true);
  });

  it("isDurable / isTransient type guards work", () => {
    const durable: AgentExecutionEvent = {
      ...baseEvent,
      type: "node.state_changed",
      channel: "durable",
      nodeId,
      state: "completed",
    };
    const transient: AgentExecutionEvent = {
      ...baseEvent,
      type: "command.output",
      channel: "transient",
      nodeId,
      data: "ls\n",
    };
    expect(isDurable(durable)).toBe(true);
    expect(isTransient(durable)).toBe(false);
    expect(isTransient(transient)).toBe(true);
    expect(isDurable(transient)).toBe(false);
  });

  it("rejects mismatched type and channel", () => {
    const result = AgentExecutionEventSchema.safeParse({
      ...baseEvent,
      type: "text.delta",
      channel: "durable",
      messageId: newMessageId(),
      partId: newPartId(),
      delta: "x",
    });
    expect(result.success).toBe(false);
  });

  it("rejects unknown event type", () => {
    const result = AgentExecutionEventSchema.safeParse({
      ...baseEvent,
      type: "agent.exploded",
      channel: "durable",
    });
    expect(result.success).toBe(false);
  });
});

describe("execution/sequence — SequenceCounter", () => {
  it("returns 0 on the first call for a session", () => {
    const c = new SequenceCounter();
    expect(c.next(newSessionId())).toBe(0);
  });

  it("increments monotonically within a session", () => {
    const c = new SequenceCounter();
    const id = newSessionId();
    expect([c.next(id), c.next(id), c.next(id), c.next(id)]).toEqual([0, 1, 2, 3]);
  });

  it("isolates counters across sessions", () => {
    const c = new SequenceCounter();
    const a: SessionID = newSessionId();
    const b: SessionID = newSessionId();
    expect(c.next(a)).toBe(0);
    expect(c.next(a)).toBe(1);
    expect(c.next(b)).toBe(0);
    expect(c.next(a)).toBe(2);
    expect(c.next(b)).toBe(1);
  });

  it("seed() resumes from a known sequence", () => {
    const c = new SequenceCounter();
    const id = newSessionId();
    c.seed(id, 42);
    expect(c.next(id)).toBe(43);
  });

  it("peek() returns null before any call and current value after", () => {
    const c = new SequenceCounter();
    const id = newSessionId();
    expect(c.peek(id)).toBeNull();
    c.next(id);
    c.next(id);
    expect(c.peek(id)).toBe(1);
  });

  it("forget() resets the counter for a session", () => {
    const c = new SequenceCounter();
    const id = newSessionId();
    c.next(id);
    c.next(id);
    c.forget(id);
    expect(c.peek(id)).toBeNull();
    expect(c.next(id)).toBe(0);
  });
});
