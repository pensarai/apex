import type { ToolResultPart } from "ai";
import { describe, expect, it } from "vitest";
import { ToolLifecycleTracker } from "./toolLifecycle";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function inputStart(id: string, toolName: string) {
  return { type: "tool-input-start", id, toolName };
}
function inputDelta(id: string, delta: string) {
  return { type: "tool-input-delta", id, delta };
}
function toolCall(id: string, toolName: string) {
  return { type: "tool-call", toolCallId: id, toolName };
}
function toolResult(id: string, toolName: string, output: unknown) {
  return { type: "tool-result", toolCallId: id, toolName, output };
}

// ---------------------------------------------------------------------------
// ToolLifecycleTracker
// ---------------------------------------------------------------------------

describe("ToolLifecycleTracker", () => {
  it("tracks a normal completion: in-flight → result, kept until step persisted", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "execute_command"));
    t.observePart(inputDelta("tc-1", '{"command":"ls"}'));
    t.observePart(toolCall("tc-1", "execute_command"));
    expect(t.inFlightTools.get("tc-1")).toBe("execute_command");

    t.observePart(toolResult("tc-1", "execute_command", { ok: true }));
    expect(t.inFlightTools.size).toBe(0);
    expect(t.completedResults).toHaveLength(1);
    expect(t.completedResults[0]).toMatchObject({
      toolCallId: "tc-1",
      output: { ok: true },
    });
    expect(t.hasUnpersistedState()).toBe(true);

    t.onStepPersisted();
    expect(t.completedResults).toHaveLength(0);
    expect(t.hasUnpersistedState()).toBe(false);
  });

  it("accumulates streamed argument text across deltas", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "t"));
    t.observePart(inputDelta("tc-1", '{"a":'));
    t.observePart(inputDelta("tc-1", "1}"));
    expect(t.streamedArgText.get("tc-1")).toBe('{"a":1}');
  });

  it("records tool errors with parsed input preferred over streamed text", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "response"));
    t.observePart(inputDelta("tc-1", '{"partial'));
    t.observePart(toolCall("tc-1", "response"));
    t.observePart({
      type: "tool-error",
      toolCallId: "tc-1",
      toolName: "response",
      input: { real: "args" },
      error: new Error("schema mismatch"),
    });

    expect(t.inFlightTools.size).toBe(0);
    const err = t.toolErrors.get("tc-1");
    expect(err?.message).toBe("schema mismatch");
    expect(err?.input).toEqual({ real: "args" });
    expect(err?.toolName).toBe("response");
  });

  it("falls back to streamed arg text when the error input is tiny or absent", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "t"));
    t.observePart(inputDelta("tc-1", '{"trunc'));
    t.observePart({
      type: "tool-error",
      toolCallId: "tc-1",
      toolName: "t",
      input: {},
      error: "boom",
    });
    expect(t.toolErrors.get("tc-1")?.input).toBe('{"trunc');

    const t2 = new ToolLifecycleTracker();
    t2.observePart({
      type: "tool-error",
      toolCallId: "tc-2",
      toolName: "t",
      error: { code: 500 },
    });
    expect(t2.toolErrors.get("tc-2")?.message).toBe(
      JSON.stringify({ code: 500 }),
    );
    expect(t2.toolErrors.get("tc-2")?.input).toBe("");
  });

  it("handles duplicate parts idempotently for in-flight tracking", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "t"));
    t.observePart(toolCall("tc-1", "t")); // duplicate registration
    expect(t.inFlightTools.size).toBe(1);

    t.observePart(toolResult("tc-1", "t", "a"));
    t.observePart(toolResult("tc-1", "t", "b")); // duplicate result
    expect(t.inFlightTools.size).toBe(0);
    // Completed results append verbatim — dedup is not the tracker's call.
    expect(t.completedResults).toHaveLength(2);
  });

  it("flushToolErrorsToResults records error-text results and clears the map", () => {
    const t = new ToolLifecycleTracker();
    t.observePart({
      type: "tool-error",
      toolCallId: "tc-1",
      toolName: "t",
      error: "late failure",
    });

    const flushed = t.flushToolErrorsToResults();
    expect(flushed).toHaveLength(1);
    expect(flushed[0]?.[0]).toBe("tc-1");
    expect(t.completedResults).toHaveLength(1);
    expect(t.completedResults[0]).toMatchObject({
      toolCallId: "tc-1",
      output: {
        type: "error-text",
        value: "Tool call failed: late failure",
      },
    });
    expect(t.toolErrors.size).toBe(0);

    // Second flush is empty.
    expect(t.flushToolErrorsToResults()).toHaveLength(0);
    expect(t.completedResults).toHaveLength(1);
  });

  it("clearToolErrors / clearInFlight drop state without recording results", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "t"));
    t.observePart({
      type: "tool-error",
      toolCallId: "tc-2",
      toolName: "t",
      error: "x",
    });

    t.clearToolErrors();
    t.clearInFlight();
    expect(t.toolErrors.size).toBe(0);
    expect(t.inFlightTools.size).toBe(0);
    expect(t.completedResults).toHaveLength(0);
  });

  it("snapshot() is an independent copy — mutation and later parts never alter it", () => {
    const t = new ToolLifecycleTracker();
    t.observePart(inputStart("tc-1", "t"));
    t.observePart(inputDelta("tc-1", '{"a":1}'));

    const snap = t.snapshot();
    // Mutate the snapshot's maps like a hostile consumer that bypasses the
    // readonly types — the tracker must not see any of it.
    (snap.inFlightTools as Map<string, string>).set("tc-hack", "hacked");
    (snap.streamedArgText as Map<string, string>).set("tc-hack", "hacked");
    (snap.completedResults as ToolResultPart[]).push({
      type: "tool-result",
      toolCallId: "tc-hack",
      toolName: "h",
      output: { type: "text", value: "x" },
    });
    expect(t.inFlightTools.has("tc-hack")).toBe(false);
    expect(t.completedResults).toHaveLength(0);

    // Further stream parts don't alter the earlier snapshot.
    t.observePart(toolResult("tc-1", "t", "done"));
    expect(snap.inFlightTools.get("tc-1")).toBe("t");
    expect(snap.completedResults).toHaveLength(1); // the hacked entry only
    expect(snap.streamedArgText.get("tc-1")).toBe('{"a":1}');

    const snap2 = t.snapshot();
    expect(snap2.inFlightTools.size).toBe(0);
    expect(snap2.completedResults).toHaveLength(1);
    expect(snap2).not.toBe(snap);
  });

  it("ignores non-tool parts", () => {
    const t = new ToolLifecycleTracker();
    t.observePart({ type: "text-delta", delta: "hi" });
    t.observePart({ type: "start-step" });
    t.observePart({ type: "finish-step" });
    expect(t.hasUnpersistedState()).toBe(false);
    expect(t.inFlightTools.size).toBe(0);
    expect(t.completedResults).toHaveLength(0);
  });
});
