import { describe, expect, it, vi } from "vitest";
import type { DisplayMessage } from "../agent-display";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  markSubagentsInterrupted,
  type SubagentSession,
} from "./subagent-state";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function toolMessage(
  status: "streaming" | "pending" | "completed" | "error",
  toolCallId = "tc-1",
): DisplayMessage {
  return {
    role: "tool",
    content: "execute_command",
    createdAt: new Date("2026-08-25T00:00:00Z"),
    toolCallId,
    toolName: "execute_command",
    args: {},
    status,
  };
}

function textMessage(text: string): DisplayMessage {
  return {
    role: "assistant",
    content: text,
    createdAt: new Date("2026-08-25T00:00:01Z"),
  };
}

function makeSession(
  overrides: Partial<SubagentSession> = {},
): SubagentSession {
  return {
    id: "sub-1",
    name: "Subagent 1",
    status: "running",
    spawnedAt: new Date("2026-08-25T00:00:00Z"),
    input: null,
    messages: [],
    ...overrides,
  };
}

describe("SubagentStore counts", () => {
  it("keeps stable snapshots and skips notifications for identity no-ops", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);
    const sessions = store.getSnapshot();
    const counts = store.getCountsSnapshot();
    const listener = vi.fn();
    store.subscribe(listener);
    store.subscribeCounts(listener);

    store.setState(sessions);
    store.setState((previous) => previous);
    helpers.appendText("missing", "ignored");
    helpers.completeSession("missing", "completed");
    store.setState(markSubagentsInterrupted);

    expect(store.getSnapshot()).toBe(sessions);
    expect(store.getCountsSnapshot()).toBe(counts);
    expect(counts).toEqual({
      total: 0,
      running: 0,
      completed: 0,
      failed: 0,
      cancelled: 0,
    });
    expect(listener).not.toHaveBeenCalled();
  });

  it("publishes every text/tool update only to full-map listeners without mutating old snapshots", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);
    helpers.spawnSession("sub-1");
    const counts = store.getCountsSnapshot();
    const fullListener = vi.fn();
    const countListener = vi.fn();
    store.subscribe(fullListener);
    store.subscribeCounts(countListener);
    const history = [];
    const updates = [
      () => helpers.appendText("sub-1", "hello"),
      () => helpers.appendText("sub-1", "\nworld"),
      () => helpers.addStreamingToolCall("sub-1", "tool-1", "execute_command"),
      () => helpers.appendToolCallDelta("sub-1", "tool-1", '{"command":"ec'),
      () => helpers.appendToolCallDelta("sub-1", "tool-1", 'ho ok"}'),
      () =>
        helpers.addToolCall("sub-1", "tool-1", "execute_command", {
          command: "echo ok",
        }),
      () => helpers.updateToolResult("sub-1", "tool-1", "ok\n"),
    ];
    for (const update of updates) {
      const previous = store.getSnapshot();
      history.push({ snapshot: previous, value: structuredClone(previous) });
      update();
      expect(store.getSnapshot()).not.toBe(previous);
      expect(store.getCountsSnapshot()).toBe(counts);
    }
    for (const { snapshot, value } of history) expect(snapshot).toEqual(value);
    expect(fullListener).toHaveBeenCalledTimes(updates.length);
    expect(countListener).not.toHaveBeenCalled();
    expect(store.getSnapshot().get("sub-1")?.messages).toMatchObject([
      { role: "assistant", content: "hello\nworld" },
      {
        role: "tool",
        args: { command: "echo ok" },
        status: "completed",
        result: "ok\n",
      },
    ]);
  });

  it("publishes coherent snapshots before either listener runs through lifecycle transitions", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);
    const observe = () => {
      const sessions = [...store.getSnapshot().values()];
      expect(store.getCountsSnapshot()).toEqual({
        total: sessions.length,
        running: sessions.filter((s) => s.status === "running").length,
        completed: sessions.filter((s) => s.status === "completed").length,
        failed: sessions.filter((s) => s.status === "failed").length,
        cancelled: sessions.filter((s) => s.status === "cancelled").length,
      });
    };
    const fullListener = vi.fn(observe);
    const countListener = vi.fn(observe);
    store.subscribe(fullListener);
    store.subscribeCounts(countListener);
    const initial = store.getCountsSnapshot();
    helpers.spawnSession("sub-1");
    const running = store.getCountsSnapshot();
    helpers.spawnSession("sub-1", "replaced while running");
    expect(store.getCountsSnapshot()).toBe(running);
    helpers.completeSession("sub-1", "completed");
    const completed = store.getCountsSnapshot();
    helpers.completeSession("sub-1", "completed");
    expect(store.getCountsSnapshot()).toBe(completed);
    helpers.completeSession("sub-1", "failed");
    const failed = store.getCountsSnapshot();
    helpers.spawnSession("sub-1");
    store.setState(markSubagentsInterrupted);
    const cancelled = store.getCountsSnapshot();

    expect([initial, running, completed, failed, cancelled]).toEqual([
      { total: 0, running: 0, completed: 0, failed: 0, cancelled: 0 },
      { total: 1, running: 1, completed: 0, failed: 0, cancelled: 0 },
      { total: 1, running: 0, completed: 1, failed: 0, cancelled: 0 },
      { total: 1, running: 0, completed: 0, failed: 1, cancelled: 0 },
      { total: 1, running: 0, completed: 0, failed: 0, cancelled: 1 },
    ]);
    expect(fullListener).toHaveBeenCalledTimes(7);
    expect(countListener).toHaveBeenCalledTimes(5);
  });

  it("counts bulk restore, removal, clear and discovery after clear", () => {
    const store = createSubagentStore();
    const listener = vi.fn();
    store.subscribeCounts(listener);
    const restored = new Map([
      ["a", makeSession({ id: "a", status: "completed" })],
      ["b", makeSession({ id: "b", status: "failed" })],
      ["c", makeSession({ id: "c", status: "cancelled" })],
    ]);
    store.setState(restored);
    expect(store.getSnapshot()).toBe(restored);
    const restoredCounts = store.getCountsSnapshot();
    expect(restoredCounts).toEqual({
      total: 3,
      running: 0,
      completed: 1,
      failed: 1,
      cancelled: 1,
    });
    store.setState((previous) => {
      const next = new Map(previous);
      next.delete("b");
      return next;
    });
    expect(store.getCountsSnapshot()).toEqual({
      total: 2,
      running: 0,
      completed: 1,
      failed: 0,
      cancelled: 1,
    });
    expect(restored.size).toBe(3);
    store.setState(new Map());
    const cleared = store.getCountsSnapshot();
    expect(cleared).toEqual({
      total: 0,
      running: 0,
      completed: 0,
      failed: 0,
      cancelled: 0,
    });
    store.setState(new Map());
    expect(store.getCountsSnapshot()).toBe(cleared);
    store.setState(restored);
    expect(store.getCountsSnapshot()).toEqual(restoredCounts);
    expect(listener).toHaveBeenCalledTimes(4);
  });

  it("keeps counts stable across replacement, reordering and status swaps with equal totals", () => {
    const store = createSubagentStore();
    store.setState(
      new Map([
        ["a", makeSession({ id: "a" })],
        ["b", makeSession({ id: "b", status: "completed" })],
      ]),
    );
    const counts = store.getCountsSnapshot();
    const fullListener = vi.fn();
    const countListener = vi.fn();
    store.subscribe(fullListener);
    store.subscribeCounts(countListener);
    store.setState(
      new Map([
        ["d", makeSession({ id: "d", status: "completed" })],
        ["c", makeSession({ id: "c", messages: [textMessage("new")] })],
      ]),
    );
    store.setState(
      (previous) =>
        new Map(
          [...previous].map(([id, session]) => [
            id,
            {
              ...session,
              status: session.status === "running" ? "completed" : "running",
            },
          ]),
        ),
    );
    expect(store.getCountsSnapshot()).toBe(counts);
    expect(fullListener).toHaveBeenCalledTimes(2);
    expect(countListener).not.toHaveBeenCalled();
  });

  it("does not notify counts when interruption only settles tools", () => {
    const store = createSubagentStore();
    const session = makeSession({
      status: "failed",
      messages: [toolMessage("pending")],
    });
    store.setState(new Map([[session.id, session]]));
    const counts = store.getCountsSnapshot();
    const fullListener = vi.fn();
    const countListener = vi.fn();
    store.subscribe(fullListener);
    store.subscribeCounts(countListener);
    store.setState(markSubagentsInterrupted);
    store.setState(markSubagentsInterrupted);
    expect(store.getCountsSnapshot()).toBe(counts);
    expect(store.getSnapshot().get(session.id)?.messages[0]).toMatchObject({
      status: "error",
      result: "Interrupted",
    });
    expect(session.messages[0].status).toBe("pending");
    expect(fullListener).toHaveBeenCalledTimes(1);
    expect(countListener).not.toHaveBeenCalled();
  });

  it("isolates store instances and independently unsubscribes both channels", () => {
    const store = createSubagentStore();
    const other = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);
    const listener = vi.fn();
    const otherListener = vi.fn();
    const unsubscribeFull = store.subscribe(listener);
    const unsubscribeCounts = store.subscribeCounts(listener);
    other.subscribe(otherListener);
    other.subscribeCounts(otherListener);
    const otherCounts = other.getCountsSnapshot();
    helpers.spawnSession("sub-1");
    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribeCounts();
    unsubscribeCounts();
    helpers.completeSession("sub-1", "completed");
    expect(listener).toHaveBeenCalledTimes(3);
    unsubscribeFull();
    const resubscribed = store.subscribeCounts(listener);
    helpers.completeSession("sub-1", "failed");
    expect(listener).toHaveBeenCalledTimes(4);
    resubscribed();
    store.setState(new Map());
    expect(listener).toHaveBeenCalledTimes(4);
    expect(otherListener).not.toHaveBeenCalled();
    expect(other.getCountsSnapshot()).toBe(otherCounts);
    expect(other.getSnapshot().size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// markSubagentsInterrupted
// ---------------------------------------------------------------------------

describe("markSubagentsInterrupted", () => {
  it("marks a running session cancelled, leaving its settled messages untouched", () => {
    const msg = textMessage("working");
    const sessions = new Map([["sub-1", makeSession({ messages: [msg] })]]);

    const result = markSubagentsInterrupted(sessions);

    const session = result.get("sub-1");
    expect(session?.status).toBe("cancelled");
    // Settled messages pass through by reference.
    expect(session?.messages[0]).toBe(msg);
  });

  it("leaves settled sessions without in-flight tools untouched by reference", () => {
    const settled = makeSession({
      id: "sub-2",
      status: "completed",
      completedAt: new Date("2026-08-25T00:00:05Z"),
      messages: [toolMessage("completed")],
    });
    const sessions = new Map([["sub-2", settled]]);

    const result = markSubagentsInterrupted(sessions);

    expect(result.get("sub-2")).toBe(settled);
  });

  it("interrupts in-flight tools on a session that already settled", () => {
    const completedTool = toolMessage("completed", "tc-done");
    const pendingTool = toolMessage("pending", "tc-pending");
    const streamingTool = toolMessage("streaming", "tc-streaming");
    const sessions = new Map([
      [
        "sub-1",
        makeSession({
          status: "failed",
          messages: [completedTool, pendingTool, streamingTool],
        }),
      ],
    ]);

    const result = markSubagentsInterrupted(sessions);

    const session = result.get("sub-1");
    // Status is preserved — only the "running → cancelled" flip happens.
    expect(session?.status).toBe("failed");
    expect(session?.messages[0]).toBe(completedTool);
    expect(session?.messages[1]).toMatchObject({
      status: "error",
      result: "Interrupted",
      toolCallId: "tc-pending",
    });
    expect(session?.messages[2]).toMatchObject({
      status: "error",
      result: "Interrupted",
      toolCallId: "tc-streaming",
    });
  });

  it("flips status and interrupts tools together for a running session", () => {
    const sessions = new Map([
      [
        "sub-1",
        makeSession({
          messages: [textMessage("hi"), toolMessage("streaming")],
        }),
      ],
    ]);

    const result = markSubagentsInterrupted(sessions);

    const session = result.get("sub-1");
    expect(session?.status).toBe("cancelled");
    expect(session?.messages[1]).toMatchObject({
      status: "error",
      result: "Interrupted",
    });
  });

  it("returns the identical reference for an empty store", () => {
    const sessions = new Map<string, SubagentSession>();

    const result = markSubagentsInterrupted(sessions);

    expect(result).toBe(sessions);
  });

  it("returns the identical reference when nothing needs changing", () => {
    const sessions = new Map([
      ["sub-1", makeSession({ status: "completed", messages: [] })],
    ]);

    const result = markSubagentsInterrupted(sessions);

    expect(result).toBe(sessions);
  });

  it("preserves insertion order across changed and unchanged sessions", () => {
    const sessions = new Map([
      ["sub-a", makeSession({ id: "sub-a", status: "running" })],
      ["sub-b", makeSession({ id: "sub-b", status: "completed" })],
      ["sub-c", makeSession({ id: "sub-c", status: "failed" })],
    ]);

    const result = markSubagentsInterrupted(sessions);

    expect(Array.from(result.keys())).toEqual(["sub-a", "sub-b", "sub-c"]);
  });

  it("does not mutate the input map, sessions, or messages", () => {
    const pendingTool = toolMessage("pending");
    const session = makeSession({
      messages: [textMessage("working"), pendingTool],
    });
    const sessions = new Map([["sub-1", session]]);
    const originalMap = structuredClone(Object.fromEntries(sessions.entries()));

    markSubagentsInterrupted(sessions);

    expect(Object.fromEntries(sessions.entries())).toEqual(originalMap);
    expect(session.status).toBe("running");
    expect(pendingTool.status).toBe("pending");
    expect(pendingTool.result).toBeUndefined();
  });
});
