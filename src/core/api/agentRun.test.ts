import { describe, it, expect } from "vitest";
import { AgentRun } from "./agentRun";
import type { AgentEvent } from "../agents/offSecAgent/eventBus";

describe("AgentRun", () => {
  // ---------------------------------------------------------------------------
  // Existing tests (updated to account for terminal events)
  // ---------------------------------------------------------------------------

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

    // 2 text-delta + 1 run-complete
    expect(events).toHaveLength(3);
    expect(events[0]!.type).toBe("text-delta");
    expect(events[1]!.type).toBe("text-delta");
    expect(events[2]!.type).toBe("run-complete");
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

    // 3 domain events + 1 run-complete
    expect(events).toHaveLength(4);
    expect(events[0]!.type).toBe("text-delta");
    expect(events[1]!.type).toBe("tool-call");
    expect(events[2]!.type).toBe("text-delta");
    expect(events[3]!.type).toBe("run-complete");
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

    // At least 1 text-delta + 1 run-error terminal event
    expect(events.length).toBeGreaterThanOrEqual(2);
    expect(events[events.length - 1]!.type).toBe("run-error");
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

    // Only the run-complete terminal event
    expect(events).toHaveLength(1);
    expect(events[0]!.type).toBe("run-complete");
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

    // 3 text-delta + 1 run-complete
    expect(events).toHaveLength(4);
    expect(events[3]!.type).toBe("run-complete");
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

    // 2 domain events + 1 run-complete
    expect(events).toHaveLength(3);
    expect(events[0]!.subagentId).toBe("agent-1");
    expect(events[1]!.subagentId).toBeUndefined();
    expect(events[2]!.type).toBe("run-complete");
  });

  // ---------------------------------------------------------------------------
  // New tests: AgentRun hardening
  // ---------------------------------------------------------------------------

  describe("id", () => {
    it("assigns a unique UUID to each run", async () => {
      const run1 = new AgentRun<void>(async () => {});
      const run2 = new AgentRun<void>(async () => {});

      expect(run1.id).toBeTruthy();
      expect(run2.id).toBeTruthy();
      expect(run1.id).not.toBe(run2.id);

      // UUID v4 format
      expect(run1.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );

      await run1.result;
      await run2.result;
    });
  });

  describe("terminal events", () => {
    it("emits run-complete on successful completion", async () => {
      const events: AgentEvent[] = [];

      const run = new AgentRun<string>(async (bus) => {
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "hi" } as any });
        return "ok";
      });

      for await (const event of run) {
        events.push(event);
      }

      const last = events[events.length - 1]!;
      expect(last.type).toBe("run-complete");
      expect(await run.result).toBe("ok");
    });

    it("emits run-error with normalized error on thrown Error", async () => {
      const events: AgentEvent[] = [];

      const run = new AgentRun<never>(async () => {
        throw new Error("something broke");
      });

      for await (const event of run) {
        events.push(event);
      }

      const last = events[events.length - 1]!;
      expect(last.type).toBe("run-error");
      if (last.type === "run-error") {
        expect(last.error.message).toBe("something broke");
        expect(last.error.name).toBe("Error");
      }

      await expect(run.result).rejects.toThrow("something broke");
    });

    it("emits run-cancelled when abort error is thrown", async () => {
      const events: AgentEvent[] = [];

      const run = new AgentRun<never>(async () => {
        const err = new DOMException("The operation was aborted.", "AbortError");
        throw err;
      });

      for await (const event of run) {
        events.push(event);
      }

      const last = events[events.length - 1]!;
      expect(last.type).toBe("run-cancelled");
      if (last.type === "run-cancelled") {
        expect(last.error.message).toBe("The operation was aborted.");
        expect(last.error.name).toBe("AbortError");
      }

      await expect(run.result).rejects.toThrow();
    });

    it("emits run-cancelled for Error with name AbortError", async () => {
      const events: AgentEvent[] = [];

      const run = new AgentRun<never>(async () => {
        const err = new Error("aborted");
        err.name = "AbortError";
        throw err;
      });

      for await (const event of run) {
        events.push(event);
      }

      const last = events[events.length - 1]!;
      expect(last.type).toBe("run-cancelled");
      if (last.type === "run-cancelled") {
        expect(last.error.name).toBe("AbortError");
      }

      await expect(run.result).rejects.toThrow();
    });

    it("terminal event is the last event before iterator closes", async () => {
      const events: AgentEvent[] = [];

      const run = new AgentRun<void>(async (bus) => {
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "a" } as any });
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "b" } as any });
      });

      for await (const event of run) {
        events.push(event);
      }

      const terminalTypes = ["run-complete", "run-error", "run-cancelled"];
      // Last event should be terminal
      expect(terminalTypes).toContain(events[events.length - 1]!.type);
      // No non-terminal events after the terminal event
      const terminalIdx = events.findIndex((e) => terminalTypes.includes(e.type));
      expect(terminalIdx).toBe(events.length - 1);
    });
  });

  describe("normalizeError", () => {
    it("normalizes Error instances to { message, name }", () => {
      const run = new AgentRun<void>(async () => {});

      const normalized = run.normalizeError(new TypeError("bad type"));
      expect(normalized).toEqual({
        message: "bad type",
        name: "TypeError",
      });

      return run.result;
    });

    it("normalizes Error with code property", () => {
      const run = new AgentRun<void>(async () => {});

      const err = new Error("ENOENT") as Error & { code: string };
      err.code = "ENOENT";
      const normalized = run.normalizeError(err);
      expect(normalized).toEqual({
        message: "ENOENT",
        name: "Error",
        code: "ENOENT",
      });

      return run.result;
    });

    it("normalizes string errors to { message }", () => {
      const run = new AgentRun<void>(async () => {});

      const normalized = run.normalizeError("raw string error");
      expect(normalized).toEqual({ message: "raw string error" });

      return run.result;
    });

    it("normalizes non-string, non-Error values via String()", () => {
      const run = new AgentRun<void>(async () => {});

      expect(run.normalizeError(42)).toEqual({ message: "42" });
      expect(run.normalizeError(null)).toEqual({ message: "null" });
      expect(run.normalizeError(undefined)).toEqual({ message: "undefined" });

      return run.result;
    });
  });
});
