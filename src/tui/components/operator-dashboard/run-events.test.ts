import { describe, expect, it, vi } from "vitest";
import type { AgentEventBus, AgentEventMap } from "../../../core/eventBus";
import { AgentEventBus as Bus } from "../../../core/eventBus";
import type { DisplayMessage, WorkflowData } from "../agent-display";
import {
  bindOperatorRunEvents,
  createDisplayEventHandlers,
  createRunEventProjections,
  type OperatorRunEventHandlers,
  type SubagentEventSink,
} from "./run-events";
import { initialWorkflowData } from "./workflow-data";

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

// ---------------------------------------------------------------------------
// createDisplayEventHandlers — display projections
// ---------------------------------------------------------------------------

describe("createDisplayEventHandlers", () => {
  function createRecordingSink() {
    let messages: DisplayMessage[] = [];
    const thinking: boolean[] = [];
    const errors: string[] = [];
    const sink = {
      updateMessages: (updater: (m: typeof messages) => typeof messages) => {
        messages = updater(messages);
      },
      setThinking: (v: boolean) => thinking.push(v),
      setError: (m: string) => errors.push(m),
    };
    return {
      sink,
      getMessages: () => messages,
      getThinking: () => thinking,
      getErrors: () => errors,
    };
  }

  it("replays a full streaming trace: text → tool-input → tool-call → command-output → tool-result", () => {
    const recording = createRecordingSink();
    const display = createDisplayEventHandlers(recording.sink);
    const bus = new Bus();
    bindOperatorRunEvents(bus, {
      isCurrent: () => true,
      handlers: {
        onTextDelta: display.onTextDelta,
        onToolCallStart: display.onToolCallStart,
        onToolCallDelta: display.onToolCallDelta,
        onToolCallComplete: display.onToolCallComplete,
        onCommandOutput: display.onCommandOutput,
        onToolResult: display.onToolResult,
      },
    });

    // Partial assistant text streams in.
    bus.emit("text-delta", { text: "Let me " });
    bus.emit("text-delta", { text: "run a scan." });
    expect(display.getPartialText()).toBe("Let me run a scan.");

    // Tool input starts streaming.
    bus.emit("tool-call-start", {
      toolCallId: "tc-1",
      toolName: "execute_command",
    });
    expect(display.getPartialText()).toBe("");

    // Args JSON arrives in fragments; only complete parses project.
    bus.emit("tool-call-delta", {
      toolCallId: "tc-1",
      argsTextDelta: '{"command":"nmap -p 443 ',
    });
    bus.emit("tool-call-delta", {
      toolCallId: "tc-1",
      argsTextDelta: 'example.com"}',
    });

    // The call completes with final args.
    bus.emit("tool-call-complete", {
      toolCallId: "tc-1",
      toolName: "execute_command",
      args: { command: "nmap -p 443 example.com" },
    });

    // Command output streams (buffered, throttled).
    bus.emit("command-output", { data: "Starting Nmap 7.94\n" });

    // The tool produces its result — output flushes first, then completion.
    bus.emit("tool-result", {
      toolCallId: "tc-1",
      toolName: "execute_command",
      result: { exitCode: 0 },
    });

    const messages = recording.getMessages();
    expect(messages).toHaveLength(2);
    expect(messages[0]).toMatchObject({
      role: "assistant",
      content: "Let me run a scan.",
    });
    expect(messages[1]).toMatchObject({
      role: "tool",
      toolCallId: "tc-1",
      toolName: "execute_command",
      status: "completed",
      args: { command: "nmap -p 443 example.com" },
      result: { exitCode: 0 },
    });
    expect(messages[1].logs).toEqual(["Starting Nmap 7.94", ""]);
    // Thinking toggles: text/tool events clear it; a tool result restores it.
    // (Two text deltas → two false entries.)
    expect(recording.getThinking()).toEqual([false, false, false, false, true]);
    // Partial text is reset by the tool lifecycle.
    expect(display.getPartialText()).toBe("");
    display.dispose();
  });

  it("buffers command output and flushes on the 150ms throttle timer", () => {
    vi.useFakeTimers();
    try {
      const recording = createRecordingSink();
      const display = createDisplayEventHandlers(recording.sink);
      display.onToolCallStart({ toolCallId: "tc-1", toolName: "t" });

      display.onCommandOutput({ data: "line-1\n" });
      display.onCommandOutput({ data: "line-2\n" });
      expect(recording.getMessages()).toHaveLength(1);

      vi.advanceTimersByTime(150);
      const messages = recording.getMessages();
      expect(messages).toHaveLength(1);
      expect(messages[0].logs).toEqual(["line-1", "line-2", ""]);

      // Buffer drained — a later timer tick flushes nothing new.
      vi.advanceTimersByTime(150);
      expect(recording.getMessages()).toHaveLength(1);

      display.dispose();
    } finally {
      vi.useRealTimers();
    }
  });

  it("stopCommandOutputFlush halts the throttle; dispose clears the timer", () => {
    vi.useFakeTimers();
    try {
      const recording = createRecordingSink();
      const display = createDisplayEventHandlers(recording.sink);
      display.onToolCallStart({ toolCallId: "tc-1", toolName: "t" });

      display.onCommandOutput({ data: "buffered\n" });
      display.stopCommandOutputFlush();
      vi.advanceTimersByTime(1000);
      // Timer stopped — nothing flushed into the active tool's logs.
      expect(recording.getMessages()[0].logs).toBeUndefined();

      // Explicit flush still drains the buffer.
      display.flushCommandOutput();
      expect(recording.getMessages()[0].logs).toEqual(["buffered", ""]);

      // dispose clears an active timer without flushing.
      display.onCommandOutput({ data: "more\n" });
      display.dispose();
      vi.advanceTimersByTime(1000);
      expect(recording.getMessages()[0].logs).toEqual(["buffered", ""]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("error projection sets the error and marks in-flight tools errored", () => {
    const recording = createRecordingSink();
    const display = createDisplayEventHandlers(recording.sink);
    display.onToolCallStart({ toolCallId: "tc-1", toolName: "t" });

    display.onError({ error: new Error("stream died") });

    expect(recording.getErrors()).toEqual(["stream died"]);
    const messages = recording.getMessages();
    expect(messages[0]).toMatchObject({
      status: "error",
      result: "stream died",
    });
    display.dispose();
  });

  it("unparseable args deltas do not touch the display", () => {
    const recording = createRecordingSink();
    const display = createDisplayEventHandlers(recording.sink);
    let updates = 0;
    const countingSink = {
      ...recording.sink,
      updateMessages: (u: (m: DisplayMessage[]) => DisplayMessage[]) => {
        updates++;
        recording.sink.updateMessages(u);
      },
    };
    const display2 = createDisplayEventHandlers(countingSink);

    display2.onToolCallDelta({ toolCallId: "tc-1", argsTextDelta: '{"comm' });
    expect(updates).toBe(0);

    display.dispose();
  });
});

// ---------------------------------------------------------------------------
// createRunEventProjections — subagent routing, questions, workflow phases
// ---------------------------------------------------------------------------

describe("createRunEventProjections", () => {
  function setup(current = true) {
    let messages: DisplayMessage[] = [];
    const display = createDisplayEventHandlers({
      updateMessages: (u) => {
        messages = u(messages);
      },
      setThinking: () => {},
      setError: () => {},
    });
    const subagents: SubagentEventSink = {
      appendText: vi.fn(),
      addStreamingToolCall: vi.fn(),
      appendToolCallDelta: vi.fn(),
      addToolCall: vi.fn(),
      updateToolResult: vi.fn(),
      spawnSession: vi.fn(),
      completeSession: vi.fn(),
    };
    const workflowUpdaters: Array<(wd: WorkflowData) => WorkflowData> = [];
    const clearSubagentSessions = vi.fn();
    const onAsked = vi.fn();
    const onCleared = vi.fn();
    const onRootToolCallStarted = vi.fn();
    const onPlanSubmitted = vi.fn();
    const projections = createRunEventProjections({
      display,
      subagents,
      updateWorkflowData: (u) => workflowUpdaters.push(u),
      clearSubagentSessions,
      questions: { onAsked, onCleared },
      onRootToolCallStarted,
      onPlanSubmitted,
    });
    const bus = new Bus();
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: () => current,
      handlers: projections.handlers,
    });
    return {
      display,
      subagents,
      workflowUpdaters,
      clearSubagentSessions,
      onAsked,
      onCleared,
      onRootToolCallStarted,
      onPlanSubmitted,
      bus,
      unbind,
      getMessages: () => messages,
    };
  }

  it("routes root events to the display and subagent events to the sink", () => {
    const s = setup();

    s.bus.emit("text-delta", { text: "root text" });
    s.bus.emit("text-delta", { text: " sub", subagentId: "pentest-agent-1" });
    expect(s.getMessages()).toHaveLength(1);
    expect(s.getMessages()[0]).toMatchObject({
      role: "assistant",
      content: "root text",
    });
    expect(s.subagents.appendText).toHaveBeenCalledWith(
      "pentest-agent-1",
      " sub",
    );

    s.bus.emit("tool-call-start", {
      toolCallId: "tc-sub",
      toolName: "t",
      subagentId: "pentest-agent-1",
    });
    expect(s.subagents.addStreamingToolCall).toHaveBeenCalledWith(
      "pentest-agent-1",
      "tc-sub",
      "t",
    );
    expect(s.getMessages()).toHaveLength(1);

    // Subagent command output is dropped entirely.
    s.bus.emit("command-output", { data: "x", subagentId: "pentest-agent-1" });
    expect(s.getMessages()).toHaveLength(1);

    s.bus.emit("error", {
      error: new Error("sub fail"),
      subagentId: "pentest-agent-1",
    });
    expect(s.subagents.appendText).toHaveBeenCalledWith(
      "pentest-agent-1",
      expect.stringContaining("sub fail"),
    );
    expect(s.getMessages()).toHaveLength(1);

    // Subagent tool-call-complete falls back to {} args.
    s.bus.emit("tool-call-complete", {
      toolCallId: "tc-sub",
      toolName: "t",
      args: undefined,
      subagentId: "pentest-agent-1",
    });
    expect(s.subagents.addToolCall).toHaveBeenCalledWith(
      "pentest-agent-1",
      "tc-sub",
      "t",
      {},
    );
    s.unbind();
  });

  it("drops every projection for stale generations", () => {
    const s = setup(false);

    s.bus.emit("text-delta", { text: "stale" });
    s.bus.emit("subagent-spawn", {
      subagentId: "pentest-agent-1",
      input: {},
    });
    s.bus.emit("workflow-phase-start", { phase: "discovery", label: "Recon" });

    expect(s.getMessages()).toHaveLength(0);
    expect(s.subagents.spawnSession).not.toHaveBeenCalled();
    expect(s.clearSubagentSessions).not.toHaveBeenCalled();
    expect(s.workflowUpdaters).toHaveLength(0);
    s.unbind();
  });

  it("intercepts ask_user_questions and fires root tool-call hooks", () => {
    const s = setup();

    s.bus.emit("tool-call-complete", {
      toolCallId: "q1",
      toolName: "ask_user_questions",
      args: { questions: [{ id: "x", question: "which?" }] },
    });
    expect(s.onAsked).toHaveBeenCalledWith("q1", [
      { id: "x", question: "which?" },
    ]);
    expect(s.onRootToolCallStarted).toHaveBeenCalledTimes(1);

    // Empty questions batch — no interception.
    s.bus.emit("tool-call-complete", {
      toolCallId: "q2",
      toolName: "ask_user_questions",
      args: { questions: [] },
    });
    expect(s.onAsked).toHaveBeenCalledTimes(1);

    // Non-question tool — no interception, hook still fires.
    s.bus.emit("tool-call-complete", {
      toolCallId: "tc-1",
      toolName: "execute_command",
      args: { command: "ls" },
    });
    expect(s.onAsked).toHaveBeenCalledTimes(1);
    // Three root tool-call-completes total (q1, empty q2, tc-1).
    expect(s.onRootToolCallStarted).toHaveBeenCalledTimes(3);
    s.unbind();
  });

  it("clears questions on root error and tracks submit_plan success", () => {
    const s = setup();

    s.bus.emit("error", { error: new Error("boom") });
    expect(s.onCleared).toHaveBeenCalledTimes(1);

    s.bus.emit("tool-result", {
      toolCallId: "p1",
      toolName: "submit_plan",
      result: { success: true },
    });
    expect(s.onPlanSubmitted).toHaveBeenCalledTimes(1);

    // Unsuccessful submit_plan — no gating flip.
    s.bus.emit("tool-result", {
      toolCallId: "p2",
      toolName: "submit_plan",
      result: { success: false },
    });
    expect(s.onPlanSubmitted).toHaveBeenCalledTimes(1);
    s.unbind();
  });

  it("projects workflow phases and the subagent swarm", () => {
    const s = setup();

    s.bus.emit("text-delta", { text: "partial" });
    s.bus.emit("workflow-phase-start", { phase: "discovery", label: "Recon" });
    expect(s.display.getPartialText()).toBe("");
    expect(s.clearSubagentSessions).toHaveBeenCalledTimes(1);
    const discovery = s.workflowUpdaters[0](initialWorkflowData());
    expect(discovery.currentPhase).toBe("discovery");
    expect(discovery.discovery.label).toBe("Recon");

    // Non-discovery phase start does not clear sessions again.
    s.bus.emit("workflow-phase-start", {
      phase: "pentesting",
      label: "Exploit",
    });
    expect(s.clearSubagentSessions).toHaveBeenCalledTimes(1);

    // Synthetic app: nodes are dropped before any bookkeeping.
    s.bus.emit("subagent-spawn", { subagentId: "app:foo", input: {} });
    expect(s.subagents.spawnSession).not.toHaveBeenCalled();

    // Swarm agents register in the workflow; other subagents do not.
    s.bus.emit("subagent-spawn", {
      subagentId: "pentest-agent-1",
      name: "A1",
      input: {},
    });
    expect(s.subagents.spawnSession).toHaveBeenCalledWith(
      "pentest-agent-1",
      "A1",
    );
    const spawned = s.workflowUpdaters.at(-1)?.(initialWorkflowData());
    expect(spawned?.pentesting.subagents["pentest-agent-1"]).toMatchObject({
      name: "A1",
      status: "pending",
    });

    s.bus.emit("subagent-spawn", { subagentId: "discovery-agent", input: {} });
    expect(s.subagents.spawnSession).toHaveBeenCalledWith(
      "discovery-agent",
      undefined,
    );
    expect(s.workflowUpdaters).toHaveLength(3);

    s.bus.emit("subagent-complete", {
      subagentId: "pentest-agent-1",
      status: "completed",
    });
    expect(s.subagents.completeSession).toHaveBeenCalledWith(
      "pentest-agent-1",
      "completed",
    );
    const completed = s.workflowUpdaters.at(-1)?.(spawned as WorkflowData);
    expect(completed?.pentesting.subagents["pentest-agent-1"].status).toBe(
      "completed",
    );

    s.bus.emit("workflow-phase-complete", {
      phase: "reporting",
      summary: { findingsCount: 2 },
    });
    const reported = s.workflowUpdaters.at(-1)?.(completed as WorkflowData);
    expect(reported?.currentPhase).toBe("complete");
    expect(reported?.reporting.findingsCount).toBe(2);
    s.unbind();
  });

  it("cleanup stops all forwarding", () => {
    const s = setup();
    s.unbind();

    s.bus.emit("text-delta", { text: "after" });
    s.bus.emit("subagent-spawn", { subagentId: "pentest-agent-1", input: {} });
    s.bus.emit("workflow-phase-start", { phase: "discovery", label: "R" });

    expect(s.getMessages()).toHaveLength(0);
    expect(s.subagents.spawnSession).not.toHaveBeenCalled();
    expect(s.workflowUpdaters).toHaveLength(0);
  });
});
