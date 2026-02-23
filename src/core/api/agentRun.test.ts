import { describe, it, expect } from "vitest";
import { AgentRun } from "./agentRun";
import type { AgentEventBus } from "../agents/offSecAgent/eventBus";
import type { AgentEvent } from "../agents/offSecAgent/eventBus";

describe("AgentRun", () => {
  it("iterates events then resolves result", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<string>(async (bus) => {
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "hello " } as any });
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "world" } as any });
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
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "ignored" } as any });
      return 42;
    });

    const result = await run.result;
    expect(result).toBe(42);
  });

  it("buffers events while consumer is processing", async () => {
    const events: AgentEvent[] = [];

    const run = new AgentRun<void>(async (bus) => {
      // Emit several events synchronously
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "a" } as any });
      bus.emit({ type: "tool-call", data: { type: "tool-call", toolName: "test", toolCallId: "1", args: {} } as any });
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "b" } as any });
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
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "before error" } as any });
      throw new Error("boom");
    });

    for await (const event of run) {
      events.push(event);
    }

    expect(events.length).toBeGreaterThanOrEqual(1);
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
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "first" } as any });
      await new Promise((r) => setTimeout(r, 10));
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "second" } as any });
      await new Promise((r) => setTimeout(r, 10));
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "third" } as any });
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
      child.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "from child" } as any });
      bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "from parent" } as any });
    });

    for await (const event of run) {
      events.push(event);
    }

    // Child event should have subagentId, parent should not
    expect(events).toHaveLength(2);
    expect(events[0]!.subagentId).toBe("agent-1");
    expect(events[1]!.subagentId).toBeUndefined();
  });
});
