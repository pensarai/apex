import type { ModelMessage, ToolResultPart } from "ai";
import { describe, expect, it } from "vitest";
import {
  baseContainsToolCalls,
  buildInterruptedStepMessages,
  buildSyntheticToolResults,
} from "./interruptedStepMessages";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const inFlight = new Map<string, string>([
  ["tc-open-1", "execute_command"],
  ["tc-open-2", "response"],
]);

function completed(ids: string[]): ToolResultPart[] {
  return ids.map((id) => ({
    type: "tool-result",
    toolCallId: id,
    toolName: `tool-${id}`,
    output: { type: "text", value: `done-${id}` },
  }));
}

const userBase: ModelMessage[] = [
  { role: "user", content: [{ type: "text", text: "go" }] },
];

function assistantBaseWith(ids: string[]): ModelMessage[] {
  return [
    ...userBase,
    {
      role: "assistant",
      content: ids.map((id) => ({
        type: "tool-call" as const,
        toolCallId: id,
        toolName: `tool-${id}`,
        input: {},
      })),
    },
  ];
}

// ---------------------------------------------------------------------------
// buildSyntheticToolResults
// ---------------------------------------------------------------------------

describe("buildSyntheticToolResults", () => {
  it("closes every open tool with the aborted reason", () => {
    const parts = buildSyntheticToolResults({
      inFlightTools: inFlight,
      reason: "Agent aborted by user",
      responseToolName: "response",
      responseSubmitted: false,
    });

    expect(parts).toHaveLength(2);
    expect(parts[0]).toMatchObject({
      toolCallId: "tc-open-1",
      toolName: "execute_command",
      output: {
        type: "error-text",
        value: "Tool execution aborted: Agent aborted by user",
      },
    });
    expect(parts[1]?.output).toMatchObject({
      type: "error-text",
      value: "Tool execution aborted: Agent aborted by user",
    });
  });

  it("marks an already-fired response tool as submitted, not aborted", () => {
    const parts = buildSyntheticToolResults({
      inFlightTools: inFlight,
      reason: "stream wedged",
      responseToolName: "response",
      responseSubmitted: true,
    });

    expect(parts[1]?.output).toEqual({
      type: "text",
      value: "Response submitted.",
    });
    // Non-response tools still read as aborted.
    expect(parts[0]?.output).toMatchObject({ type: "error-text" });
  });

  it("returns empty for no open tools", () => {
    expect(
      buildSyntheticToolResults({
        inFlightTools: new Map(),
        reason: "x",
        responseToolName: "response",
        responseSubmitted: false,
      }),
    ).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// baseContainsToolCalls
// ---------------------------------------------------------------------------

describe("baseContainsToolCalls", () => {
  it("true only when every id is present in the assistant content", () => {
    const base = assistantBaseWith(["tc-1", "tc-2"]);
    expect(
      baseContainsToolCalls(base[1] as ModelMessage, new Set(["tc-1"])),
    ).toBe(true);
    expect(
      baseContainsToolCalls(base[1] as ModelMessage, new Set(["tc-1", "tc-2"])),
    ).toBe(true);
    expect(
      baseContainsToolCalls(base[1] as ModelMessage, new Set(["tc-1", "tc-3"])),
    ).toBe(false);
  });

  it("false for non-array content and user messages", () => {
    expect(baseContainsToolCalls(userBase[0], new Set(["tc-1"]))).toBe(false);
    const textMsg: ModelMessage = {
      role: "assistant",
      content: "plain text",
    };
    expect(baseContainsToolCalls(textMsg, new Set(["tc-1"]))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildInterruptedStepMessages
// ---------------------------------------------------------------------------

describe("buildInterruptedStepMessages", () => {
  it("reconstructs assistant tool-calls + tool results when the base has no assistant turn", () => {
    const synthetic = buildSyntheticToolResults({
      inFlightTools: inFlight,
      reason: "aborted",
      responseToolName: "response",
      responseSubmitted: false,
    });
    const done = completed(["tc-done-1"]);
    const streamed = new Map<string, string>([
      ["tc-open-1", '{"command":"nmap"}'],
      ["tc-done-1", '{"a":1}'],
    ]);

    const { appended, needsStepReconstruction } = buildInterruptedStepMessages({
      base: userBase,
      inFlightTools: inFlight,
      completedResults: done,
      syntheticParts: synthetic,
      streamedArgText: streamed,
    });

    expect(needsStepReconstruction).toBe(true);
    expect(appended).toHaveLength(2);

    const assistant = appended[0] as {
      role: string;
      content: Array<Record<string, unknown>>;
    };
    expect(assistant.role).toBe("assistant");
    // Ordering: in-flight tools first, then completed results.
    expect(assistant.content.map((p) => p.toolCallId)).toEqual([
      "tc-open-1",
      "tc-open-2",
      "tc-done-1",
    ]);
    // Parsed streamed args preserved.
    expect(assistant.content[0]).toMatchObject({
      type: "tool-call",
      input: { command: "nmap" },
    });

    const tool = appended[1] as { role: string; content: ToolResultPart[] };
    expect(tool.role).toBe("tool");
    // Completed results first, then synthetic closes.
    expect(tool.content.map((p) => p.toolCallId)).toEqual([
      "tc-done-1",
      "tc-open-1",
      "tc-open-2",
    ]);
  });

  it("preserves malformed partial JSON as { _partial } and falls back to {}", () => {
    const single = new Map<string, string>([["tc-1", "execute_command"]]);
    const synthetic = buildSyntheticToolResults({
      inFlightTools: single,
      reason: "aborted",
      responseToolName: "response",
      responseSubmitted: false,
    });

    const { appended } = buildInterruptedStepMessages({
      base: userBase,
      inFlightTools: single,
      completedResults: [],
      syntheticParts: synthetic,
      streamedArgText: new Map([["tc-1", '{"trunc']]),
    });
    const assistant = appended[0] as {
      content: Array<Record<string, unknown>>;
    };
    expect(assistant.content[0]?.input).toEqual({ _partial: '{"trunc' });

    const { appended: noText } = buildInterruptedStepMessages({
      base: userBase,
      inFlightTools: new Map([["tc-2", "t"]]),
      completedResults: [],
      syntheticParts: [],
      streamedArgText: new Map(),
    });
    const noTextAssistant = noText[0] as {
      content: Array<Record<string, unknown>>;
    };
    expect(noTextAssistant.content[0]?.input).toEqual({});
  });

  it("skips reconstruction when the base's last assistant turn already carries every call", () => {
    const done = completed(["tc-1"]);
    const base = assistantBaseWith(["tc-1"]);
    const synthetic = buildSyntheticToolResults({
      inFlightTools: new Map(),
      reason: "aborted",
      responseToolName: "response",
      responseSubmitted: false,
    });

    const { appended, needsStepReconstruction } = buildInterruptedStepMessages({
      base,
      inFlightTools: new Map(),
      completedResults: done,
      syntheticParts: synthetic,
    });

    expect(needsStepReconstruction).toBe(false);
    // Only the tool message appends — pairing lives in the existing base.
    expect(appended).toHaveLength(1);
    expect(appended[0]?.role).toBe("tool");
  });

  it("reconstructs when the base's assistant turn is missing some ids", () => {
    const base = assistantBaseWith(["tc-1"]);
    const done = completed(["tc-1", "tc-2"]);

    const { needsStepReconstruction } = buildInterruptedStepMessages({
      base,
      inFlightTools: new Map(),
      completedResults: done,
      syntheticParts: [],
    });

    expect(needsStepReconstruction).toBe(true);
  });

  it("every reconstructed tool-call has a paired result in the tool message", () => {
    const synthetic = buildSyntheticToolResults({
      inFlightTools: inFlight,
      reason: "aborted",
      responseToolName: "response",
      responseSubmitted: false,
    });
    const done = completed(["tc-done-1"]);

    const { appended } = buildInterruptedStepMessages({
      base: userBase,
      inFlightTools: inFlight,
      completedResults: done,
      syntheticParts: synthetic,
    });

    const assistant = appended[0] as {
      content: Array<Record<string, unknown>>;
    };
    const tool = appended[1] as { content: Array<Record<string, unknown>> };
    const callIds = assistant.content.map((p) => p.toolCallId);
    const resultIds = tool.content.map((p) => p.toolCallId);
    expect(new Set(callIds)).toEqual(new Set(resultIds));
    for (const id of callIds) {
      expect(resultIds).toContain(id);
    }
  });

  it("does not mutate the base", () => {
    const base = userBase;
    const original = structuredClone(base);
    buildInterruptedStepMessages({
      base,
      inFlightTools: inFlight,
      completedResults: completed(["tc-x"]),
      syntheticParts: [],
    });
    expect(base).toEqual(original);
  });
});
