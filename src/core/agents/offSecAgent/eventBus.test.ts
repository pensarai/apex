import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  AgentEventBus,
  type AgentEvent,
  type TextDeltaData,
  type ToolCallData,
  type ToolResultData,
} from "./eventBus";

function makeTextDelta(text: string): TextDeltaData {
  return { type: "text-delta", id: "td-1", text } as TextDeltaData;
}

function makeToolCall(toolName: string): ToolCallData {
  return {
    type: "tool-call",
    toolCallId: "tc-1",
    toolName,
    args: {},
  } as unknown as ToolCallData;
}

function makeToolResult(toolName: string): ToolResultData {
  return {
    type: "tool-result",
    toolCallId: "tr-1",
    toolName,
    result: "ok",
  } as unknown as ToolResultData;
}

describe("AgentEventBus", () => {
  let bus: AgentEventBus;

  beforeEach(() => {
    bus = new AgentEventBus();
  });

  describe("emit and subscribe (unfiltered)", () => {
    it("delivers events to unfiltered subscribers", () => {
      const received: AgentEvent[] = [];
      bus.on((e) => received.push(e));

      const event: AgentEvent = {
        type: "text-delta",
        data: makeTextDelta("hello"),
      };
      bus.emit(event);

      expect(received).toHaveLength(1);
      expect(received[0]).toEqual(event);
    });

    it("delivers events to multiple unfiltered subscribers", () => {
      const a: AgentEvent[] = [];
      const b: AgentEvent[] = [];
      bus.on((e) => a.push(e));
      bus.on((e) => b.push(e));

      bus.emit({ type: "text-delta", data: makeTextDelta("hi") });

      expect(a).toHaveLength(1);
      expect(b).toHaveLength(1);
    });
  });

  describe("type-filtered subscriptions", () => {
    it("only delivers matching event types", () => {
      const textDeltas: AgentEvent[] = [];
      const toolCalls: AgentEvent[] = [];

      bus.on("text-delta", (e) => textDeltas.push(e));
      bus.on("tool-call", (e) => toolCalls.push(e));

      bus.emit({ type: "text-delta", data: makeTextDelta("a") });
      bus.emit({ type: "tool-call", data: makeToolCall("nmap") });
      bus.emit({ type: "text-delta", data: makeTextDelta("b") });

      expect(textDeltas).toHaveLength(2);
      expect(toolCalls).toHaveLength(1);
      expect(toolCalls[0].type).toBe("tool-call");
    });

    it("delivers to both unfiltered and type-filtered subscribers", () => {
      const all: AgentEvent[] = [];
      const errorsOnly: AgentEvent[] = [];

      bus.on((e) => all.push(e));
      bus.on("error", (e) => errorsOnly.push(e));

      bus.emit({ type: "text-delta", data: makeTextDelta("x") });
      bus.emit({ type: "error", error: new Error("boom") });

      expect(all).toHaveLength(2);
      expect(errorsOnly).toHaveLength(1);
      expect(errorsOnly[0].type).toBe("error");
    });

    it("handles subagent-spawn and subagent-complete event types", () => {
      const spawns: AgentEvent[] = [];
      const completions: AgentEvent[] = [];

      bus.on("subagent-spawn", (e) => spawns.push(e));
      bus.on("subagent-complete", (e) => completions.push(e));

      bus.emit({
        type: "subagent-spawn",
        subagentId: "agent-1",
        input: { target: "example.com" },
        status: "pending",
      });
      bus.emit({
        type: "subagent-complete",
        subagentId: "agent-1",
        input: { target: "example.com" },
        status: "completed",
      });

      expect(spawns).toHaveLength(1);
      expect(completions).toHaveLength(1);
    });

    it("handles tool-result events", () => {
      const results: AgentEvent[] = [];
      bus.on("tool-result", (e) => results.push(e));

      bus.emit({ type: "tool-result", data: makeToolResult("nmap") });
      bus.emit({ type: "text-delta", data: makeTextDelta("ignored") });

      expect(results).toHaveLength(1);
    });
  });

  describe("unsubscribe", () => {
    it("unsubscribes an unfiltered handler", () => {
      const received: AgentEvent[] = [];
      const unsub = bus.on((e) => received.push(e));

      bus.emit({ type: "text-delta", data: makeTextDelta("a") });
      expect(received).toHaveLength(1);

      unsub();

      bus.emit({ type: "text-delta", data: makeTextDelta("b") });
      expect(received).toHaveLength(1);
    });

    it("unsubscribes a type-filtered handler", () => {
      const received: AgentEvent[] = [];
      const unsub = bus.on("tool-call", (e) => received.push(e));

      bus.emit({ type: "tool-call", data: makeToolCall("nmap") });
      expect(received).toHaveLength(1);

      unsub();

      bus.emit({ type: "tool-call", data: makeToolCall("curl") });
      expect(received).toHaveLength(1);
    });

    it("does not affect other subscribers when one unsubscribes", () => {
      const a: AgentEvent[] = [];
      const b: AgentEvent[] = [];

      const unsubA = bus.on("text-delta", (e) => a.push(e));
      bus.on("text-delta", (e) => b.push(e));

      bus.emit({ type: "text-delta", data: makeTextDelta("1") });
      expect(a).toHaveLength(1);
      expect(b).toHaveLength(1);

      unsubA();

      bus.emit({ type: "text-delta", data: makeTextDelta("2") });
      expect(a).toHaveLength(1);
      expect(b).toHaveLength(2);
    });
  });

  describe("child bus", () => {
    it("auto-tags events with subagentId", () => {
      const received: AgentEvent[] = [];
      bus.on((e) => received.push(e));

      const child = bus.child("agent-1");
      child.emit({ type: "text-delta", data: makeTextDelta("from child") });

      expect(received).toHaveLength(1);
      expect(received[0].subagentId).toBe("agent-1");
    });

    it("does not overwrite an existing subagentId on the event", () => {
      const received: AgentEvent[] = [];
      bus.on((e) => received.push(e));

      const child = bus.child("agent-1");
      child.emit({
        type: "text-delta",
        subagentId: "already-set",
        data: makeTextDelta("pre-tagged"),
      });

      expect(received).toHaveLength(1);
      expect(received[0].subagentId).toBe("already-set");
    });

    it("bubbles events to the parent bus", () => {
      const parentEvents: AgentEvent[] = [];
      bus.on((e) => parentEvents.push(e));

      const child = bus.child("child-1");
      child.emit({ type: "error", error: "something broke" });

      expect(parentEvents).toHaveLength(1);
      expect(parentEvents[0].type).toBe("error");
      expect(parentEvents[0].subagentId).toBe("child-1");
    });

    it("delivers to child-local subscribers AND parent", () => {
      const parentEvents: AgentEvent[] = [];
      const childEvents: AgentEvent[] = [];

      bus.on((e) => parentEvents.push(e));

      const child = bus.child("c1");
      child.on((e) => childEvents.push(e));

      child.emit({ type: "text-delta", data: makeTextDelta("both") });

      expect(childEvents).toHaveLength(1);
      expect(parentEvents).toHaveLength(1);
      expect(childEvents[0].subagentId).toBe("c1");
      expect(parentEvents[0].subagentId).toBe("c1");
    });

    it("supports type-filtered subscriptions on child bus", () => {
      const childToolCalls: AgentEvent[] = [];

      const child = bus.child("c1");
      child.on("tool-call", (e) => childToolCalls.push(e));

      child.emit({ type: "text-delta", data: makeTextDelta("ignored") });
      child.emit({ type: "tool-call", data: makeToolCall("curl") });

      expect(childToolCalls).toHaveLength(1);
    });
  });

  describe("nested child buses", () => {
    it("bubbles through multiple levels to root", () => {
      const rootEvents: AgentEvent[] = [];
      bus.on((e) => rootEvents.push(e));

      const level1 = bus.child("orchestrator");
      const level2 = level1.child("pentest-agent-0");

      level2.emit({ type: "text-delta", data: makeTextDelta("deep") });

      expect(rootEvents).toHaveLength(1);
      expect(rootEvents[0].subagentId).toBe("pentest-agent-0");
    });

    it("each level receives bubbled events", () => {
      const rootEvents: AgentEvent[] = [];
      const level1Events: AgentEvent[] = [];
      const level2Events: AgentEvent[] = [];

      bus.on((e) => rootEvents.push(e));

      const level1 = bus.child("l1");
      level1.on((e) => level1Events.push(e));

      const level2 = level1.child("l2");
      level2.on((e) => level2Events.push(e));

      level2.emit({ type: "tool-call", data: makeToolCall("scan") });

      expect(level2Events).toHaveLength(1);
      expect(level1Events).toHaveLength(1);
      expect(rootEvents).toHaveLength(1);
    });
  });

  describe("edge cases", () => {
    it("does not throw when emitting with no subscribers", () => {
      expect(() => {
        bus.emit({ type: "text-delta", data: makeTextDelta("lonely") });
      }).not.toThrow();
    });

    it("calling unsubscribe multiple times is safe", () => {
      const received: AgentEvent[] = [];
      const unsub = bus.on((e) => received.push(e));

      unsub();
      unsub();

      bus.emit({ type: "text-delta", data: makeTextDelta("test") });
      expect(received).toHaveLength(0);
    });

    it("root bus events have no subagentId", () => {
      const received: AgentEvent[] = [];
      bus.on((e) => received.push(e));

      bus.emit({ type: "text-delta", data: makeTextDelta("root") });

      expect(received[0].subagentId).toBeUndefined();
    });
  });
});
