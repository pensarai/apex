import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AgentEventBus } from "../../../core/eventBus";
import type { DisplayMessage } from "../agent-display";
import { recoverAbortedTranscript } from "./conversation";
import {
  createDisplayMessageUpdater,
  markInFlightToolsErrored,
} from "./display-state";
import {
  bindOperatorRunEvents,
  createDisplayEventHandlers,
} from "./run-events";

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function setup() {
  let messages: DisplayMessage[] = [];
  const update = vi.fn(
    (apply: (previous: DisplayMessage[]) => DisplayMessage[]) => {
      messages = apply(messages);
    },
  );
  const display = createDisplayEventHandlers({
    updateMessages: update,
    setThinking: () => {},
    setError: () => {},
  });
  display.onToolCallStart({ toolCallId: "a", toolName: "create_file" });
  return { display, update, messages: () => messages };
}

it("publishes the latest preview at 33ms without postponing for later deltas", () => {
  const { display, messages, update } = setup();
  display.onToolCallDelta({
    toolCallId: "a",
    argsTextDelta: '{"content":"first',
  });
  vi.advanceTimersByTime(32);
  display.onToolCallDelta({ toolCallId: "a", argsTextDelta: " second" });
  expect(messages()[0].args).toEqual({});
  vi.advanceTimersByTime(1);
  expect(messages()[0].args).toEqual({ content: "first second" });
  expect(messages()[0].logs).toEqual(["first second"]);
  expect(update).toHaveBeenCalledTimes(2);
  expect(vi.getTimerCount()).toBe(0);
  vi.advanceTimersByTime(1000);
  expect(update).toHaveBeenCalledTimes(2);
  display.dispose();
});

it("waits for more data after an unparseable prefix without polling", () => {
  const { display, messages, update } = setup();
  display.onToolCallDelta({ toolCallId: "a", argsTextDelta: '{"cont' });
  vi.advanceTimersByTime(33);
  expect(update).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(0);
  display.onToolCallDelta({ toolCallId: "a", argsTextDelta: 'ent":"ready"}' });
  vi.advanceTimersByTime(33);
  expect(messages()[0].args).toEqual({ content: "ready" });
  display.dispose();
});

it("publishes authoritative final arguments immediately and drops late previews", () => {
  const { display, messages, update } = setup();
  display.onToolCallDelta({
    toolCallId: "a",
    argsTextDelta: '{"content":"draft',
  });
  display.onToolCallComplete({
    toolCallId: "a",
    toolName: "create_file",
    args: { content: "final" },
  });
  expect(messages()[0]).toMatchObject({
    args: { content: "final" },
    status: "pending",
    logs: undefined,
  });
  display.onToolCallDelta({ toolCallId: "a", argsTextDelta: "late" });
  vi.advanceTimersByTime(1000);
  expect(update).toHaveBeenCalledTimes(2);
  expect(messages()[0].args).toEqual({ content: "final" });
  expect(vi.getTimerCount()).toBe(0);
  display.dispose();
});

it("finishing one parallel tool does not drop another tool's pending preview", () => {
  const { display, messages } = setup();
  display.onToolCallStart({ toolCallId: "b", toolName: "create_file" });
  for (const toolCallId of ["a", "b"]) {
    display.onToolCallDelta({
      toolCallId,
      argsTextDelta: `{"content":"${toolCallId}`,
    });
  }
  display.onToolCallComplete({
    toolCallId: "a",
    toolName: "create_file",
    args: { content: "final a" },
  });
  display.onToolResult({
    toolCallId: "a",
    toolName: "create_file",
    result: "done",
  });
  expect(vi.getTimerCount()).toBe(1);
  vi.advanceTimersByTime(33);
  expect(messages()[0]).toMatchObject({
    status: "completed",
    args: { content: "final a" },
  });
  expect(messages()[1]).toMatchObject({
    status: "streaming",
    args: { content: "b" },
  });
  expect(vi.getTimerCount()).toBe(0);
  display.dispose();
});

it("flushes preview and command-output tails before marking an error", () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const { display, messages } = setup();
  display.onToolCallDelta({
    toolCallId: "a",
    argsTextDelta: '{"content":"tail',
  });
  display.onCommandOutput({ data: " output" });
  display.onError({ error: new Error("failed") });
  expect(messages()[0]).toMatchObject({
    status: "error",
    args: { content: "tail" },
    logs: ["tail output"],
  });
  expect(vi.getTimerCount()).toBe(0);
  display.dispose();
});

it("preserves partial arguments when a result arrives without final arguments", () => {
  const { display, messages } = setup();
  display.onToolCallDelta({
    toolCallId: "a",
    argsTextDelta: '{"content":"partial',
  });
  display.onToolResult({
    toolCallId: "a",
    toolName: "create_file",
    result: "interrupted",
  });
  expect(messages()[0]).toMatchObject({
    args: { content: "partial" },
    result: "interrupted",
  });
  expect(vi.getTimerCount()).toBe(0);
  display.dispose();
});

it("finishes before run replacement without mixing generations or clearing recovery text", () => {
  const { display, messages } = setup();
  let generation = 1;
  const oldBus = new AgentEventBus();
  const unbind = bindOperatorRunEvents(oldBus, {
    isCurrent: () => generation === 1,
    handlers: { onToolCallDelta: display.onToolCallDelta },
  });
  oldBus.emit("tool-call-delta", {
    toolCallId: "a",
    argsTextDelta: '{"content":"old',
  });
  display.onTextDelta({ text: "recovery text" });
  generation++;
  display.finish();
  display.finish();
  expect(display.getPartialText()).toBe("recovery text");
  expect(messages()[0].args).toEqual({ content: "old" });
  expect(vi.getTimerCount()).toBe(0);
  display.onToolCallStart({ toolCallId: "b", toolName: "create_file" });
  oldBus.emit("tool-call-delta", { toolCallId: "a", argsTextDelta: " stale" });
  display.onToolCallDelta({
    toolCallId: "b",
    argsTextDelta: '{"content":"new',
  });
  vi.advanceTimersByTime(33);
  expect(messages().at(-1)?.args).toEqual({ content: "new" });
  expect(messages()[0].args).toEqual({ content: "old" });
  unbind();
  display.dispose();
});

it("discards previews on disposal and rejects further deltas for discarded calls", () => {
  const { display, update } = setup();
  display.onToolCallDelta({
    toolCallId: "a",
    argsTextDelta: '{"content":"discard',
  });
  display.dispose();
  display.onToolCallDelta({ toolCallId: "a", argsTextDelta: "late" });
  vi.advanceTimersByTime(1000);
  expect(update).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(0);
});

it("keeps captured previews ordered when React defers the sink's functional updates", () => {
  const updates: ((messages: DisplayMessage[]) => DisplayMessage[])[] = [];
  const display = createDisplayEventHandlers({
    updateMessages: (update) => updates.push(update),
    setThinking: () => {},
    setError: () => {},
  });
  display.onToolCallStart({ toolCallId: "a", toolName: "create_file" });
  display.onToolCallDelta({
    toolCallId: "a",
    argsTextDelta: '{"content":"preview',
  });
  vi.advanceTimersByTime(33);
  display.onToolCallComplete({
    toolCallId: "a",
    toolName: "create_file",
    args: { content: "final" },
  });
  const messages = updates.reduce(
    (previous, apply) => apply(previous),
    [] as DisplayMessage[],
  );
  expect(messages[0]).toMatchObject({
    status: "pending",
    args: { content: "final" },
    logs: undefined,
  });
  expect(vi.getTimerCount()).toBe(0);
  display.dispose();
});

it.each([
  "preview",
  "complete",
  "complete-without-start",
  "result",
])("recovers current arguments before React commits: %s", (phase) => {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-args-recovery-"));
  const snapshot = { current: [] as DisplayMessage[] };
  const published: DisplayMessage[][] = [];
  const updateMessages = createDisplayMessageUpdater(snapshot, (messages) =>
    published.push(messages),
  );
  const display = createDisplayEventHandlers({
    updateMessages,
    setThinking: () => {},
    setError: () => {},
  });
  try {
    if (phase !== "complete-without-start") {
      display.onToolCallStart({ toolCallId: "a", toolName: "create_file" });
      display.onToolCallDelta({
        toolCallId: "a",
        argsTextDelta: '{"content":"latest tail',
      });
    }
    if (phase !== "preview") {
      display.onToolCallComplete({
        toolCallId: "a",
        toolName: "create_file",
        args: { content: "authoritative" },
      });
    }
    if (phase === "result") {
      display.onToolResult({
        toolCallId: "a",
        toolName: "create_file",
        result: "done",
      });
    }
    display.finish();
    const recoveryMessages = snapshot.current;
    updateMessages((messages) =>
      markInFlightToolsErrored(messages, "Interrupted"),
    );
    const recovered = recoverAbortedTranscript({
      rootPath,
      conversation: [{ role: "user", content: "Write a file" }],
      partialText: display.getPartialText(),
      displayMessages: recoveryMessages,
    });
    expect(
      JSON.parse(readFileSync(join(rootPath, "messages.json"), "utf8")),
    ).toEqual(recovered);
    expect(published.length).toBeGreaterThan(0);
    if (phase === "result") {
      expect(recovered).toHaveLength(2);
    } else {
      expect(recovered[1].content).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "tool-call",
            toolCallId: "a",
            input: {
              content: phase === "preview" ? "latest tail" : "authoritative",
            },
          }),
        ]),
      );
      expect(recovered).toHaveLength(3);
      expect(snapshot.current[0].status).toBe("error");
      expect(recoveryMessages[0].status).not.toBe("error");
    }
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    display.dispose();
    rmSync(rootPath, { recursive: true, force: true });
  }
});
