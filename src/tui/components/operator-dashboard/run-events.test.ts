import { describe, expect, it, vi } from "vitest";
import type { AgentEventBus, AgentEventMap } from "../../../core/eventBus";
import { AgentEventBus as Bus } from "../../../core/eventBus";
import {
  bindOperatorRunEvents,
  type OperatorRunEventHandlers,
} from "./run-events";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type EventCase = readonly [
  event: keyof AgentEventMap,
  handlerKey: keyof OperatorRunEventHandlers,
  payload: unknown,
];

const EVENT_CASES: readonly EventCase[] = [
  ["text-delta", "onTextDelta", { text: "hello" }],
  [
    "tool-call-start",
    "onToolCallStart",
    { toolCallId: "tc-1", toolName: "execute_command" },
  ],
  [
    "tool-call-delta",
    "onToolCallDelta",
    { toolCallId: "tc-1", argsTextDelta: '{"command":' },
  ],
  [
    "tool-call-complete",
    "onToolCallComplete",
    { toolCallId: "tc-1", toolName: "execute_command", args: { a: 1 } },
  ],
  [
    "tool-result",
    "onToolResult",
    { toolCallId: "tc-1", toolName: "execute_command", result: "done" },
  ],
  ["command-output", "onCommandOutput", { data: "line\n" }],
  ["error", "onError", { error: new Error("boom") }],
  [
    "subagent-spawn",
    "onSubagentSpawn",
    { subagentId: "pentest-agent-1", input: {} },
  ],
  [
    "subagent-complete",
    "onSubagentComplete",
    { subagentId: "pentest-agent-1", status: "completed" },
  ],
  [
    "workflow-phase-start",
    "onWorkflowPhaseStart",
    { phase: "discovery", label: "Recon" },
  ],
  [
    "workflow-phase-complete",
    "onWorkflowPhaseComplete",
    { phase: "reporting", summary: { findingsCount: 2 } },
  ],
] as const;

/** Untyped emit helper for the table-driven test. */
function emit(bus: AgentEventBus, event: string, payload: unknown): void {
  (bus.emit as (event: string, payload: unknown) => boolean)(event, payload);
}

// ---------------------------------------------------------------------------
// bindOperatorRunEvents
// ---------------------------------------------------------------------------

describe("bindOperatorRunEvents", () => {
  it("forwards each event to its handler exactly once with the payload", () => {
    for (const [event, handlerKey, payload] of EVENT_CASES) {
      const bus = new Bus();
      const handler = vi.fn();
      const unbind = bindOperatorRunEvents(bus, {
        isCurrent: () => true,
        handlers: { [handlerKey]: handler } as OperatorRunEventHandlers,
      });

      emit(bus, event, payload);

      expect(handler, event).toHaveBeenCalledTimes(1);
      expect(handler, event).toHaveBeenCalledWith(payload);
      unbind();
    }
  });

  it("does not subscribe events whose handlers are omitted", () => {
    const bus = new Bus();
    const handler = vi.fn();
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: { onTextDelta: handler },
    });

    emit(bus, "tool-result", {
      toolCallId: "tc-1",
      toolName: "t",
      result: null,
    });

    expect(handler).not.toHaveBeenCalled();
    unbind();
  });

  it("drops events when the generation guard reports stale", () => {
    const bus = new Bus();
    const handler = vi.fn();
    let current = true;
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => current,
      handlers: { onTextDelta: handler },
    });

    emit(bus, "text-delta", { text: "fresh" });
    current = false;
    emit(bus, "text-delta", { text: "stale" });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith({ text: "fresh" });
    unbind();
  });

  it("cleanup detaches every listener; idempotent", () => {
    const bus = new Bus();
    const textHandler = vi.fn();
    const resultHandler = vi.fn();
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: {
        onTextDelta: textHandler,
        onToolResult: resultHandler,
      },
    });

    unbind();
    unbind(); // second call is a safe no-op

    emit(bus, "text-delta", { text: "after" });
    emit(bus, "tool-result", {
      toolCallId: "tc-1",
      toolName: "t",
      result: null,
    });

    expect(textHandler).not.toHaveBeenCalled();
    expect(resultHandler).not.toHaveBeenCalled();
  });

  it("repeated binding: unbinding one binding leaves the other intact", () => {
    const bus = new Bus();
    const first = vi.fn();
    const second = vi.fn();
    const unbindFirst = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: { onTextDelta: first },
    });
    const unbindSecond = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: { onTextDelta: second },
    });

    emit(bus, "text-delta", { text: "both" });
    unbindFirst();
    emit(bus, "text-delta", { text: "second only" });

    expect(first).toHaveBeenCalledTimes(1);
    expect(second).toHaveBeenCalledTimes(2);
    expect(second).toHaveBeenLastCalledWith({ text: "second only" });
    unbindSecond();
  });

  it("isolates listener exceptions from the emitter, siblings, and later events", () => {
    const bus = new Bus();
    const throwing = vi.fn(() => {
      throw new Error("handler boom");
    });
    const sibling = vi.fn();
    bus.on("text-delta", sibling);

    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: { onTextDelta: throwing },
    });

    expect(() => emit(bus, "text-delta", { text: "one" })).not.toThrow();

    // The sibling listener on the same emission still ran...
    expect(sibling).toHaveBeenCalledTimes(1);
    // ...and the throwing handler is still bound for later events.
    emit(bus, "text-delta", { text: "two" });
    expect(throwing).toHaveBeenCalledTimes(2);

    // Cleanup still works after the exceptions.
    unbind();
    emit(bus, "text-delta", { text: "three" });
    expect(throwing).toHaveBeenCalledTimes(2);
    // The raw sibling listener is unaffected by our unbind — 3 emissions, 3 calls.
    expect(sibling).toHaveBeenCalledTimes(3);
  });

  it("a straggler error emitted after unbind does not crash the process", () => {
    // Node's EventEmitter throws when `error` is emitted with no listeners.
    // Unbinding must leave a no-op error listener so a late emission (e.g.
    // forwarded from a subagent bus that outlived the run) is dropped.
    const bus = new Bus();
    const onError = vi.fn();
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: { onError },
    });

    unbind();

    expect(() =>
      bus.emit("error", { error: new Error("straggler") }),
    ).not.toThrow();
    expect(onError).not.toHaveBeenCalled();
  });

  it("unbind does not add an error listener when none was bound", () => {
    const bus = new Bus();
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: { onTextDelta: vi.fn() },
    });

    unbind();

    // The binding only manages the listeners it subscribed — no error
    // handler was bound, so unbind must not leave a no-op behind. Node
    // still throws on a listenerless error emission, which is exactly
    // what happens if this contract is violated.
    expect(() => bus.emit("error", { error: new Error("x") })).toThrow();
  });
});
