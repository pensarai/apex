import { describe, it, expect } from "vitest";
import { AgentRun } from "./agentRun";
import type {
  AgentEvent,
  TextDeltaData,
  ToolCallData,
} from "../agents/offSecAgent/eventBus";

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

describe("AgentRun", () => {
  it("iterates events then resolves result", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<string>(async (bus) => {
      bus.emit({ type: "text-delta", data: makeTextDelta("hello ") });
      bus.emit({ type: "text-delta", data: makeTextDelta("world") });
      return "done";
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events).toHaveLength(2);
    expect(events[0]!.type).toBe("text-delta");
    expect(events[1]!.type).toBe("text-delta");
    expect(await run.result).toBe("done");
  });

  it("resolves result without iterating", async () => {
    const run = new AgentRun<number>(async (bus) => {
      bus.emit({ type: "text-delta", data: makeTextDelta("ignored") });
      return 42;
    });

    const result = await run.result;
    expect(result).toBe(42);
  });

  it("buffers events while consumer is processing", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<void>(async (bus) => {
      // Emit several events synchronously
      bus.emit({ type: "text-delta", data: makeTextDelta("a") });
      bus.emit({ type: "tool-call", data: makeToolCall("test") });
      bus.emit({ type: "text-delta", data: makeTextDelta("b") });
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events).toHaveLength(3);
    expect(events[0]!.type).toBe("text-delta");
    expect(events[1]!.type).toBe("tool-call");
    expect(events[2]!.type).toBe("text-delta");
  });

  it("propagates errors from the agent run", async () => {
    const run = new AgentRun<never>(async () => {
      throw new Error("agent failed");
    });

    await expect(run.result).rejects.toThrow("agent failed");
  });

  it("ends iteration when agent errors", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<never>(async (bus) => {
      bus.emit({ type: "text-delta", data: makeTextDelta("before error") });
      throw new Error("boom");
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0]!.type).toBe("text-delta");
    await expect(run.result).rejects.toThrow("boom");
  });

  it("handles empty run (no events)", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<string>(async () => {
      return "empty";
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events).toHaveLength(0);
    expect(await run.result).toBe("empty");
  });

  it("handles async events with delays", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<string>(async (bus) => {
      bus.emit({ type: "text-delta", data: makeTextDelta("first") });
      await new Promise((r) => setTimeout(r, 10));
      bus.emit({ type: "text-delta", data: makeTextDelta("second") });
      await new Promise((r) => setTimeout(r, 10));
      bus.emit({ type: "text-delta", data: makeTextDelta("third") });
      return "complete";
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events).toHaveLength(3);
    expect(await run.result).toBe("complete");
  });

  it("preserves subagentId on events from child buses", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<void>(async (bus) => {
      const child = bus.child("agent-1");
      child.emit({ type: "text-delta", data: makeTextDelta("from child") });
      bus.emit({ type: "text-delta", data: makeTextDelta("from parent") });
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events).toHaveLength(2);
    expect(events[0]!.subagentId).toBe("agent-1");
    expect(events[1]!.subagentId).toBeUndefined();
  });
});
