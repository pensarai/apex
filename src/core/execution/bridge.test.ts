import { describe, expect, it } from "vitest";
import { AgentEventBus } from "../eventBus";
import { ExecutionContext } from "./context";
import type { AgentExecutionEvent } from "./events";
import { newSessionId } from "./ids";
import { attachLegacyBridge } from "./legacyBridge";

type NodeCreatedEvent = Extract<AgentExecutionEvent, { type: "node.created" }>;

function collect(bus: AgentEventBus): AgentExecutionEvent[] {
  const events: AgentExecutionEvent[] = [];
  bus.onExecution((e) => events.push(e));
  return events;
}

describe("AgentEventBus — new-channel emission", () => {
  it("delivers emitExecution payloads to onExecution subscribers", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    ctx.registerNode({ kind: "agent", name: "root", initialState: "running" });
    expect(events.length).toBe(1);
    expect(events[0]?.type).toBe("node.created");
  });

  it("forwards execution events from child bus to parent bus via attachChild", () => {
    const parent = new AgentEventBus();
    const child = new AgentEventBus();
    AgentEventBus.attachChild(child, parent, "sub-1");

    const parentEvents = collect(parent);
    const childCtx = new ExecutionContext({
      sessionId: newSessionId(),
      bus: child,
    });
    childCtx.registerNode({
      kind: "agent",
      name: "child-agent",
      initialState: "running",
    });

    expect(parentEvents.length).toBe(1);
    expect(parentEvents[0]?.type).toBe("node.created");
  });
});

describe("ExecutionContext — node lifecycle", () => {
  it("mints node IDs and emits node.created with correct payload", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const sessionId = newSessionId();
    const ctx = new ExecutionContext({ sessionId, bus });

    const rootId = ctx.registerNode({
      kind: "agent",
      name: "offsec",
      payload: { role: "offensive-security" },
      initialState: "running",
    });

    const created = events[0] as NodeCreatedEvent;
    expect(created.type).toBe("node.created");
    expect(created.node.id).toBe(rootId);
    expect(created.node.kind).toBe("agent");
    expect(created.node.parentId).toBeNull();
    expect(created.sequence).toBe(0);
    expect(created.sessionId).toBe(sessionId);
  });

  it("captures parent_tool_call_id when an agent is spawned via a tool call", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });

    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    const toolCallId = ctx.registerNode({
      kind: "tool_call",
      name: "spawn_subagent",
      parentNodeId: rootId,
      initialState: "running",
    });
    const childAgentId = ctx.registerNode({
      kind: "agent",
      name: "child",
      parentNodeId: rootId,
      parentToolCallId: toolCallId,
      initialState: "running",
    });

    const lastEvent = events[events.length - 1] as NodeCreatedEvent;
    expect(lastEvent.node.id).toBe(childAgentId);
    expect(lastEvent.node.parentToolCallId).toBe(toolCallId);
    expect(lastEvent.node.parentId).toBe(rootId);
  });

  it("assigns monotonic sequence numbers across all events", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });

    const id = ctx.registerNode({
      kind: "agent",
      name: "x",
      initialState: "running",
    });
    ctx.transitionNode(id, "completed");
    ctx.completeNode({ nodeId: id, result: { ok: true } });
    ctx.recordUsage({
      nodeId: id,
      model: "claude",
      tokensInput: 10,
      tokensOutput: 5,
    });

    expect(events.map((e) => e.sequence)).toEqual([0, 1, 2, 3]);
  });

  it("records messages and emits message.created with parts attached", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });

    const nodeId = ctx.registerNode({
      kind: "agent",
      name: "n",
      initialState: "running",
    });
    ctx.recordMessage({
      nodeId,
      role: "assistant",
      parts: [
        { type: "text", text: "hello" },
        { type: "step-finish" },
      ],
    });

    const msg = events.find((e) => e.type === "message.created");
    expect(msg).toBeTruthy();
    if (msg && msg.type === "message.created") {
      expect(msg.parts.length).toBe(2);
      expect(msg.parts[0]?.type).toBe("text");
      expect(msg.parts[1]?.type).toBe("step-finish");
      expect(msg.parts[0]?.index).toBe(0);
      expect(msg.parts[1]?.index).toBe(1);
    }
  });
});

describe("Legacy bridge — translates AgentEventMap events to new-channel events", () => {
  it("translates subagent-spawn → node.created (agent kind) with parent chain", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    attachLegacyBridge({ bus, context: ctx, rootNodeId: rootId });

    bus.emit("subagent-spawn", {
      subagentId: "sub-1",
      name: "child-agent",
      input: { task: "scan" },
    });

    const created = events.find(
      (e) => e.type === "node.created" && e.node.name === "child-agent",
    );
    expect(created).toBeTruthy();
    if (created && created.type === "node.created") {
      expect(created.node.kind).toBe("agent");
      expect(created.node.parentId).toBe(rootId);
    }

    expect(ctx.resolveLegacySubagent("sub-1")).toBeTruthy();
  });

  it("translates tool-call-complete → tool_call node, then tool-result → completion", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    attachLegacyBridge({ bus, context: ctx, rootNodeId: rootId });

    bus.emit("tool-call-complete", {
      toolCallId: "tc-1",
      toolName: "read_file",
      args: { path: "a.ts" },
    });
    bus.emit("tool-result", {
      toolCallId: "tc-1",
      toolName: "read_file",
      result: { content: "..." },
    });

    const toolCreated = events.find(
      (e) =>
        e.type === "node.created" &&
        e.node.kind === "tool_call" &&
        e.node.name === "read_file",
    );
    const toolCompleted = events.find((e) => e.type === "node.completed");
    expect(toolCreated).toBeTruthy();
    expect(toolCompleted).toBeTruthy();

    if (toolCreated && toolCreated.type === "node.created") {
      expect(toolCreated.node.parentId).toBe(rootId);
      if (toolCreated.node.kind === "tool_call") {
        expect(toolCreated.node.payload.externalToolCallId).toBe("tc-1");
      }
    }
  });

  it("nested subagents preserve hierarchy via parentSubagentId", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    attachLegacyBridge({ bus, context: ctx, rootNodeId: rootId });

    bus.emit("subagent-spawn", { subagentId: "sub-1", input: {} });
    bus.emit("subagent-spawn", {
      subagentId: "sub-2",
      input: {},
      parentSubagentId: "sub-1",
    });

    const subA = ctx.resolveLegacySubagent("sub-1");
    const subB = ctx.resolveLegacySubagent("sub-2");
    expect(subA).toBeTruthy();
    expect(subB).toBeTruthy();

    const childCreated = events.find(
      (e) => e.type === "node.created" && e.node.id === subB,
    );
    if (childCreated && childCreated.type === "node.created") {
      expect(childCreated.node.parentId).toBe(subA);
    }
  });

  it("legacy error event translates to node.state_changed with error", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    attachLegacyBridge({ bus, context: ctx, rootNodeId: rootId });

    bus.emit("error", { error: new Error("boom") });

    const errEvt = events.find((e) => e.type === "node.state_changed");
    expect(errEvt).toBeTruthy();
    if (errEvt && errEvt.type === "node.state_changed") {
      expect(errEvt.state).toBe("error");
      expect(errEvt.reason).toBe("boom");
      expect(errEvt.nodeId).toBe(rootId);
    }
  });

  it("translates workflow-phase-start/complete to workflow-kind nodes", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    attachLegacyBridge({ bus, context: ctx, rootNodeId: rootId });

    bus.emit("workflow-phase-start", {
      phase: "discovery",
      label: "Discovery Phase",
      metadata: { codebasePath: "/repo" },
    });
    bus.emit("workflow-phase-complete", {
      phase: "discovery",
      summary: { appsFound: 3 },
    });

    const created = events.find(
      (e) => e.type === "node.created" && e.node.kind === "workflow",
    );
    const completed = events.find((e) => e.type === "node.completed");
    expect(created).toBeTruthy();
    expect(completed).toBeTruthy();
    if (created && created.type === "node.created" && created.node.kind === "workflow") {
      expect(created.node.payload.phase).toBe("discovery");
      expect(created.node.payload.workflow).toBe("Discovery Phase");
      expect(created.node.parentId).toBe(rootId);
    }
  });

  it("idempotent: repeated bridge events with same legacy id do not double-create nodes", () => {
    const bus = new AgentEventBus();
    const events = collect(bus);
    const ctx = new ExecutionContext({ sessionId: newSessionId(), bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    attachLegacyBridge({ bus, context: ctx, rootNodeId: rootId });

    bus.emit("subagent-spawn", { subagentId: "sub-1", input: {} });
    bus.emit("subagent-spawn", { subagentId: "sub-1", input: {} });

    const created = events.filter(
      (e) =>
        e.type === "node.created" &&
        e.node.kind === "agent" &&
        e.node.parentId === rootId,
    );
    expect(created.length).toBe(1);
  });
});
