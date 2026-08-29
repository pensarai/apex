import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentEventBus } from "../../eventBus";
import { createInterruptedStepFinalizer } from "./interruptedStepFinalization";
import { AgentMessageWriter } from "./messagePersistence";
import { ToolLifecycleTracker } from "./toolLifecycle";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tmpDir: string;
let writes: string[];
let writeFailure: Error | null = null;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "interrupted-finalize-test-"));
  writes = [];
  writeFailure = null;
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function path(): string {
  return join(tmpDir, "messages.json");
}

function userMsg(text: string): ModelMessage {
  return { role: "user", content: [{ type: "text", text }] };
}

/** Build a real snapshot by driving the tracker with stream parts. */
function snapshotFrom(
  parts: Parameters<ToolLifecycleTracker["observePart"]>[0][],
): ReturnType<ToolLifecycleTracker["snapshot"]> {
  const tracker = new ToolLifecycleTracker();
  for (const part of parts) tracker.observePart(part);
  return tracker.snapshot();
}

function setup(overrides?: {
  bus?: AgentEventBus;
  latest?: ModelMessage[] | null;
}) {
  const bus = overrides?.bus ?? new AgentEventBus();
  const writer = new AgentMessageWriter({
    messagesPath: path(),
    writeImpl: async (p, contents) => {
      if (writeFailure) throw writeFailure;
      writes.push(contents);
      writeFileSync(p, contents);
    },
  });
  if (overrides?.latest) writer.setLatest(overrides.latest);
  const finalize = createInterruptedStepFinalizer({
    eventBus: bus,
    sessionId: "ses_test",
    subagentId: "sub_1",
    writer,
    responseToolName: "response",
    responseToolFired: () => false,
  });
  return { bus, writer, finalize };
}

// ---------------------------------------------------------------------------
// Interrupted-step finalizer
// ---------------------------------------------------------------------------

describe("createInterruptedStepFinalizer", () => {
  it("provider error: closes open tools, persists a valid transcript, resolves", async () => {
    const emitted: Array<Record<string, unknown>> = [];
    const { bus, finalize, writer } = setup();
    bus.on("tool-result", (e) => emitted.push(e as Record<string, unknown>));

    const snapshot = snapshotFrom([
      { type: "tool-input-start", id: "tc-1", toolName: "execute_command" },
      { type: "tool-input-delta", id: "tc-1", delta: '{"command":"nmap"}' },
      { type: "tool-call", toolCallId: "tc-1", toolName: "execute_command" },
    ]);

    await finalize({ snapshot, reason: "provider timeout" });

    // Every open tool got a synthetic result on the bus.
    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toMatchObject({
      toolCallId: "tc-1",
      toolName: "execute_command",
      sessionId: "ses_test",
      subagentId: "sub_1",
    });

    // The persisted transcript carries valid pairs + the streamed args.
    const written = JSON.parse(readFileSync(path(), "utf-8")) as ModelMessage[];
    expect(written.at(-2)).toMatchObject({
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolCallId: "tc-1",
          input: { command: "nmap" },
        },
      ],
    });
    expect(written.at(-1)).toMatchObject({
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          output: {
            type: "error-text",
            value: "Tool execution aborted: provider timeout",
          },
        },
      ],
    });
    expect(writer.syntheticsPersisted).toBe(true);
  });

  it("abort: same lifecycle with the abort reason", async () => {
    const { finalize } = setup();
    const snapshot = snapshotFrom([
      { type: "tool-call", toolCallId: "tc-a", toolName: "t" },
    ]);

    await finalize({ snapshot, reason: "Agent aborted by user" });

    const written = JSON.parse(readFileSync(path(), "utf-8")) as ModelMessage[];
    const tool = written.at(-1) as { content: Array<Record<string, unknown>> };
    expect(tool.content[0]?.output).toMatchObject({
      value: "Tool execution aborted: Agent aborted by user",
    });
  });

  it("listener error does not prevent persistence — and rethrows after the write", async () => {
    const bus = new AgentEventBus();
    bus.on("tool-result", () => {
      throw new Error("listener explosion");
    });
    const { finalize, writer } = setup({ bus });

    const snapshot = snapshotFrom([
      { type: "tool-call", toolCallId: "tc-1", toolName: "t" },
    ]);

    // Rejects with the listener error…
    await expect(finalize({ snapshot, reason: "stream died" })).rejects.toThrow(
      "listener explosion",
    );

    // …but persistence completed first — the invariant that matters.
    expect(writes).toHaveLength(1);
    expect(writer.syntheticsPersisted).toBe(true);
    const written = JSON.parse(readFileSync(path(), "utf-8")) as ModelMessage[];
    expect(written.at(-1)).toMatchObject({ role: "tool" });
  });

  it("persistence failure resolves without marking synthetics persisted", async () => {
    writeFailure = new Error("disk full");
    const { finalize, writer } = setup();

    const snapshot = snapshotFrom([
      { type: "tool-call", toolCallId: "tc-1", toolName: "t" },
    ]);

    // Resolves — a failed snapshot write must not become the run's error
    // (the original stream error stays primary; onFinish retries).
    await expect(finalize({ snapshot, reason: "x" })).resolves.toBeUndefined();
    expect(writer.syntheticsPersisted).toBe(false);
  });

  it("multiple interrupted tools: errors flushed, completed kept, all paired", async () => {
    const { finalize } = setup();

    // The interrupted path flushes deferred errors into completed results
    // before finalization (consume() does this via the tracker).
    const tracker = new ToolLifecycleTracker();
    for (const part of [
      // One open call with streamed args.
      { type: "tool-input-start", id: "tc-open", toolName: "nmap_tool" },
      { type: "tool-input-delta", id: "tc-open", delta: '{"target":"x"}' },
      { type: "tool-call", toolCallId: "tc-open", toolName: "nmap_tool" },
      // One completed-but-unpersisted result.
      {
        type: "tool-result",
        toolCallId: "tc-done",
        toolName: "http_tool",
        output: { ok: true },
      },
      // One deferred tool error.
      {
        type: "tool-error",
        toolCallId: "tc-err",
        toolName: "browser_tool",
        error: "crashed",
      },
    ])
      tracker.observePart(part);
    tracker.flushToolErrorsToResults();
    const flushedSnapshot = tracker.snapshot();

    await finalize({ snapshot: flushedSnapshot, reason: "aborted" });

    const written = JSON.parse(readFileSync(path(), "utf-8")) as ModelMessage[];
    const assistant = written.at(-2) as {
      content: Array<Record<string, unknown>>;
    };
    const tool = written.at(-1) as { content: Array<Record<string, unknown>> };
    const callIds = assistant.content.map((p) => p.toolCallId);
    const resultIds = tool.content.map((p) => p.toolCallId);
    expect(callIds).toEqual(["tc-open", "tc-done", "tc-err"]);
    expect(new Set(resultIds)).toEqual(new Set(callIds));
    expect(
      assistant.content.find((p) => p.toolCallId === "tc-open")?.input,
    ).toEqual({ target: "x" });
    // The flushed error result reads as error-text.
    expect(
      tool.content.find((p) => p.toolCallId === "tc-err")?.output,
    ).toMatchObject({ type: "error-text", value: "Tool call failed: crashed" });
    // The completed result's output is preserved.
    expect(
      tool.content.find((p) => p.toolCallId === "tc-done")?.output,
    ).toEqual({ ok: true });
  });

  it("no writer path: emits but persists nothing; listener errors still throw", async () => {
    const bus = new AgentEventBus();
    const emitted: unknown[] = [];
    bus.on("tool-result", (e) => emitted.push(e));
    const writer = new AgentMessageWriter({ messagesPath: null });
    const finalize = createInterruptedStepFinalizer({
      eventBus: bus,
      sessionId: "ses_test",
      writer,
      responseToolName: "response",
      responseToolFired: () => false,
    });

    const snapshot = snapshotFrom([
      { type: "tool-call", toolCallId: "tc-1", toolName: "t" },
    ]);
    await finalize({ snapshot, reason: "x" });

    expect(emitted).toHaveLength(1);
    expect(writes).toHaveLength(0);
  });

  it("drains the writer before reading the base (abort-write ordering)", async () => {
    let releaseFirst!: () => void;
    const gate = new Promise<void>((r) => (releaseFirst = r));
    const writer = new AgentMessageWriter({
      messagesPath: path(),
      writeImpl: async (p, contents) => {
        const isFirst = writes.length === 0;
        writes.push(contents);
        if (isFirst) await gate;
        writeFileSync(p, contents);
      },
    });
    const bus = new AgentEventBus();
    const finalize = createInterruptedStepFinalizer({
      eventBus: bus,
      sessionId: "ses_test",
      writer,
      responseToolName: "response",
      responseToolFired: () => false,
    });

    // An in-flight step write the snapshot must queue behind.
    const inFlight = writer.enqueueWrite([userMsg("step")]).catch(() => {});
    const snapshot = snapshotFrom([
      { type: "tool-call", toolCallId: "tc-1", toolName: "t" },
    ]);
    const done = finalize({ snapshot, reason: "aborted" });

    await Promise.resolve();
    await Promise.resolve();
    expect(writes).toHaveLength(1); // snapshot not yet written

    releaseFirst();
    await inFlight;
    await done;
    expect(writes).toHaveLength(2);
    const final = JSON.parse(writes[1] ?? "") as ModelMessage[];
    // Base from the drained write + reconstruction.
    expect(final[0]).toEqual(userMsg("step"));
    expect(final.at(-1)).toMatchObject({ role: "tool" });
  });
});
