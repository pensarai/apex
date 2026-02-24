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
  // ---------------------------------------------------------------------------
  // Existing tests (updated to account for terminal events)
  // ---------------------------------------------------------------------------

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

    // 2 text-delta + 1 run-complete
    expect(events).toHaveLength(3);
    expect(events[0]!.type).toBe("text-delta");
    expect(events[1]!.type).toBe("text-delta");
    expect(events[2]!.type).toBe("run-complete");
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
      bus.emit({ type: "text-delta", data: makeTextDelta("before error") });
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

    // 3 text-delta + 1 run-complete
    expect(events).toHaveLength(4);
    expect(events[3]!.type).toBe("run-complete");
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

  describe("seq (monotonic sequence counter)", () => {
    it("increments seq for each event including terminal", async () => {
      const run = new AgentRun<void>(async (bus) => {
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "a" } as any });
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "b" } as any });
      });

      for await (const _ of run) {
        // consume all events
      }

      // 2 text-delta + 1 run-complete = 3
      expect(run.seq).toBe(3);
    });

    it("seq starts at 0 for a fresh run", async () => {
      // Use a deferred pattern to control when events are emitted
      let emitFn: ((bus: AgentEventBus) => void) | null = null;
      const ready = new Promise<void>((resolve) => {
        emitFn = (bus) => {
          bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "a" } as any });
          resolve();
        };
      });

      const run = new AgentRun<void>(async (bus) => {
        // Wait a tick so the test can read seq before any events
        await new Promise((r) => setTimeout(r, 0));
        emitFn!(bus);
        await ready;
      });

      // Before the run function emits anything, seq should be 0
      expect(run.seq).toBe(0);

      for await (const _ of run) {}
      // After completion: 1 text-delta + 1 run-complete = 2
      expect(run.seq).toBe(2);
    });
  });

  describe("history and eventsAfter()", () => {
    it("records all events in history", async () => {
      const run = new AgentRun<void>(async (bus) => {
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "a" } as any });
        bus.emit({ type: "tool-call", data: { type: "tool-call", toolName: "test", toolCallId: "1", args: {} } as any });
      });

      for await (const _ of run) {
        // consume
      }

      const history = run.history;
      // 2 domain + 1 run-complete
      expect(history).toHaveLength(3);
      expect(history[0]!.type).toBe("text-delta");
      expect(history[1]!.type).toBe("tool-call");
      expect(history[2]!.type).toBe("run-complete");
    });

    it("history returns a copy (not a reference)", async () => {
      const run = new AgentRun<void>(async () => {});
      for await (const _ of run) {}

      const h1 = run.history;
      const h2 = run.history;
      expect(h1).not.toBe(h2);
      expect(h1).toEqual(h2);
    });

    it("eventsAfter returns events after given seq", async () => {
      const run = new AgentRun<void>(async (bus) => {
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "a" } as any }); // seq 1
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "b" } as any }); // seq 2
        bus.emit({ type: "text-delta", data: { type: "text-delta", textDelta: "c" } as any }); // seq 3
      });

      for await (const _ of run) {}

      // Total events: 3 text-delta + 1 run-complete = 4, stored at indices 0..3
      // eventsAfter(seq) returns history.slice(seq), so:
      // eventsAfter(0) = all events (from index 0 onward)
      // eventsAfter(2) = events at indices 2, 3 (third text-delta + run-complete)
      const afterTwo = run.eventsAfter(2);
      expect(afterTwo).toHaveLength(2);
      expect(afterTwo[0]!.type).toBe("text-delta");
      expect(afterTwo[1]!.type).toBe("run-complete");

      // eventsAfter(-1) returns all events
      expect(run.eventsAfter(-1)).toHaveLength(4);

      // eventsAfter(100) returns empty
      expect(run.eventsAfter(100)).toHaveLength(0);
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
