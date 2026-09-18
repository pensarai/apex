import { describe, expect, it } from "vitest";
import { convertNativeRolloutSourcesToAtif } from "./convert";
import { defaultPrompt, lookupTool, nativeSource } from "./test-fixtures";

const identity = {
  agent: { name: "apex", version: "test" },
  exporter: { name: "apex-native-evidence", version: "1" },
};

describe("native rollout evidence to ATIF conversion", () => {
  it("preserves exact context, tools, results, continuation, and native metrics", () => {
    const first = nativeSource({
      id: "turn-1",
      attemptId: "atm_turn_1",
      tools: [lookupTool],
      outputContent: [
        { type: "reasoning", text: "Inspect the fixture." },
        {
          type: "tool-call",
          toolCallId: "call_fixture",
          toolName: "lookup_fixture",
          input: { id: "fixture" },
        },
      ],
      native: {
        promptTokenIds: {
          state: "available",
          value: Array.from({ length: 12 }, (_, index) => index),
        },
        completionTokenIds: { state: "available", value: [20, 21, 22, 23] },
        logprobs: { state: "available", value: [0, -0.1, -0.2, -0.3] },
        tokenizer: {
          state: "available",
          value: { name: "fixture-tokenizer", version: "1" },
        },
      },
    });
    const second = nativeSource({
      id: "turn-2",
      attemptId: "atm_turn_2",
      idempotencyKey: "idem_fixture_002",
      turnIndex: 2,
      tools: [lookupTool],
      prompt: [
        ...defaultPrompt,
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              toolCallId: "call_fixture",
              toolName: "lookup_fixture",
              input: { id: "fixture" },
            },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "call_fixture",
              toolName: "lookup_fixture",
              output: { type: "text", value: "fixture value" },
            },
          ],
        },
        {
          role: "user",
          content: [{ type: "text", text: "Finish the summary." }],
        },
      ],
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [second, first],
      rootSourceId: "turn-1",
    });
    const documents = result.documents.ses_fixture;

    expect(documents).toHaveLength(2);
    expect(documents?.[0]).toMatchObject({
      trajectory_id: "atif_atm_turn_1",
      continued_trajectory_ref: "trajectories/atif_atm_turn_2.json",
      agent: {
        tool_definitions: [
          {
            type: "function",
            function: { name: "lookup_fixture" },
          },
        ],
      },
      final_metrics: {
        total_prompt_tokens: 12,
        total_completion_tokens: 4,
        total_cached_tokens: 2,
      },
    });
    expect(documents?.[0]?.steps.at(-1)).toMatchObject({
      source: "agent",
      reasoning_content: "Inspect the fixture.",
      tool_calls: [
        {
          tool_call_id: "call_fixture",
          function_name: "lookup_fixture",
          arguments: { id: "fixture" },
        },
      ],
      metrics: {
        prompt_token_ids: Array.from({ length: 12 }, (_, index) => index),
        completion_token_ids: [20, 21, 22, 23],
        logprobs: [0, -0.1, -0.2, -0.3],
      },
    });
    expect(
      documents?.[1]?.steps.some((step) =>
        step.observation?.results.some(
          (entry) =>
            entry.source_call_id === "call_fixture" &&
            entry.content === "fixture value",
        ),
      ),
    ).toBe(true);
    expect(
      documents?.[1]?.steps.find((step) =>
        step.tool_calls?.some((call) => call.tool_call_id === "call_fixture"),
      ),
    ).toMatchObject({
      source: "agent",
      observation: {
        results: [
          {
            source_call_id: "call_fixture",
            content: "fixture value",
          },
        ],
      },
    });
    expect(
      documents?.[1]?.steps.some(
        (step) => step.source === "system" && step.observation !== undefined,
      ),
    ).toBe(false);
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ code: "missing_tool_result" }),
    );
    expect(result.nativeSampling.logprobs).toMatchObject({
      available: 1,
      omitted: 1,
    });
  });

  it("exports only the compacted model-visible prompt supplied by evidence", () => {
    const source = nativeSource({
      prompt: [
        {
          role: "user",
          content: [
            {
              type: "text",
              text: "Summary of visible context; old transcript was discarded.",
            },
          ],
        },
      ],
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    const messages = result.documents.ses_fixture?.[0]?.steps.map(
      (step) => step.message,
    );

    expect(messages).toEqual([
      "Summary of visible context; old transcript was discarded.",
      "The fixture is complete.",
    ]);
  });

  it("writes captured media bytes as content-addressed bundle assets", () => {
    const source = nativeSource({
      prompt: [
        {
          role: "user",
          content: [
            { type: "text", text: "Inspect this image." },
            {
              type: "file",
              mediaType: "image/png",
              data: {
                $type: "bytes",
                encoding: "base64",
                value: Buffer.from("synthetic image bytes").toString("base64"),
              },
            },
          ],
        },
      ],
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    const userMessage = result.documents.ses_fixture?.[0]?.steps[0]?.message;
    const image = Array.isArray(userMessage)
      ? userMessage.find((part) => part.type === "image")
      : undefined;

    expect(image?.source.path).toMatch(/^assets\/[a-f0-9]{64}$/);
    expect(
      result.files.some(
        (file) =>
          file.kind === "asset" &&
          file.path === image?.source.path &&
          Buffer.from(file.bytes).toString() === "synthetic image bytes",
      ),
    ).toBe(true);
  });

  it("preserves interleaved streamed text and media order", () => {
    const media = Buffer.from("ordered image").toString("base64");
    const source = nativeSource({
      normalizedOutput: {
        parts: [
          { type: "text-start", id: "text-a" },
          { type: "text-delta", id: "text-a", delta: "before" },
          {
            type: "file",
            mediaType: "image/png",
            data: { $type: "bytes", encoding: "base64", value: media },
          },
          { type: "text-start", id: "text-b" },
          { type: "text-delta", id: "text-b", delta: "after" },
          {
            type: "finish",
            finishReason: { unified: "stop", raw: "stop" },
            usage: {
              inputTokens: { total: 12, cacheRead: 2 },
              outputTokens: { total: 4 },
            },
          },
        ],
      },
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    const message = result.documents.ses_fixture?.[0]?.steps.at(-1)?.message;

    expect(message).toEqual([
      { type: "text", text: "before" },
      {
        type: "image",
        source: {
          media_type: "image/png",
          path: expect.stringMatching(/^assets\/[a-f0-9]{64}$/),
        },
      },
      { type: "text", text: "after" },
    ]);
  });

  it("reports external media whose bytes are unavailable without inventing them", () => {
    const source = nativeSource({
      prompt: [
        {
          role: "user",
          content: [
            {
              type: "file",
              mediaType: "audio/mp3",
              data: {
                $type: "url",
                value: "https://offline.example.invalid/audio.mp3",
              },
            },
          ],
        },
      ],
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(result.documents.ses_fixture?.[0]?.steps[0]?.message).toEqual([
      {
        type: "audio",
        source: {
          media_type: "audio/mpeg",
          path: "https://offline.example.invalid/audio.mp3",
        },
      },
    ]);
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: "external_asset_not_archived" }),
    );
  });

  it("keeps misaligned native sampling in source evidence instead of invalid ATIF metrics", () => {
    const source = nativeSource({
      native: {
        promptTokenIds: { state: "available", value: [1] },
        logprobs: { state: "available", value: [0, -0.5] },
      },
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    const metrics = result.documents.ses_fixture?.[0]?.steps.at(-1)?.metrics;

    expect(metrics?.prompt_token_ids).toBeUndefined();
    expect(metrics?.logprobs).toBeUndefined();
    expect(
      result.diagnostics.filter(
        (entry) => entry.code === "misaligned_native_metric",
      ),
    ).toHaveLength(2);
  });

  it("preserves parallel tool identity and results", () => {
    const calls = ["call-a", "call-b"];
    const first = nativeSource({
      id: "parallel-1",
      attemptId: "atm_parallel_1",
      outputContent: calls.map((toolCallId) => ({
        type: "tool-call",
        toolCallId,
        toolName: "lookup_fixture",
        input: { id: toolCallId },
      })),
    });
    const second = nativeSource({
      id: "parallel-2",
      attemptId: "atm_parallel_2",
      idempotencyKey: "idem_parallel_2",
      turnIndex: 2,
      prompt: [
        {
          role: "assistant",
          content: calls.map((toolCallId) => ({
            type: "tool-call",
            toolCallId,
            toolName: "lookup_fixture",
            input: { id: toolCallId },
          })),
        },
        {
          role: "tool",
          content: calls.map((toolCallId) => ({
            type: "tool-result",
            toolCallId,
            output: { type: "text", value: `result-${toolCallId}` },
          })),
        },
      ],
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [first, second],
      rootSourceId: first.id,
    });

    expect(
      result.documents.ses_fixture?.[0]?.steps
        .at(-1)
        ?.tool_calls?.map((call) => call.tool_call_id),
    ).toEqual(calls);
    expect(
      result.documents.ses_fixture?.[1]?.steps
        .flatMap((step) => step.observation?.results ?? [])
        .map((entry) => entry.source_call_id),
    ).toEqual(calls);
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ code: "missing_tool_result" }),
    );
  });

  it("links nested sessions once through their authoritative parent tool calls", () => {
    const parent = nativeSource({
      id: "parent-source",
      sessionId: "ses-parent",
      attemptId: "atm_parent",
      outputContent: [
        {
          type: "tool-call",
          toolCallId: "call-child",
          toolName: "spawn_agent",
          input: { name: "child" },
        },
      ],
    });
    const child = nativeSource({
      id: "child-source",
      sessionId: "ses-child",
      attemptId: "atm_child",
      idempotencyKey: "idem_child",
      parent: { sessionId: "ses-parent", toolCallId: "call-child" },
      outputContent: [
        {
          type: "tool-call",
          toolCallId: "call-grandchild",
          toolName: "spawn_agent",
          input: { name: "grandchild" },
        },
      ],
    });
    const grandchild = nativeSource({
      id: "grandchild-source",
      sessionId: "ses-grandchild",
      attemptId: "atm_grandchild",
      idempotencyKey: "idem_grandchild",
      parent: {
        sessionId: "ses-child",
        toolCallId: "call-grandchild",
      },
    });

    const result = convertNativeRolloutSourcesToAtif({
      ...identity,
      sources: [grandchild, child, parent],
      rootSourceId: parent.id,
    });
    const references = Object.values(result.documents)
      .flat()
      .flatMap((document) => document.steps)
      .flatMap((step) => step.observation?.results ?? [])
      .flatMap((entry) => entry.subagent_trajectory_ref ?? [])
      .sort((left, right) =>
        (left.session_id ?? "").localeCompare(right.session_id ?? ""),
      );

    expect(references).toEqual([
      {
        trajectory_id: "atif_atm_child",
        trajectory_path: "trajectories/atif_atm_child.json",
        session_id: "ses-child",
      },
      {
        trajectory_id: "atif_atm_grandchild",
        trajectory_path: "trajectories/atif_atm_grandchild.json",
        session_id: "ses-grandchild",
      },
    ]);
    expect(
      result.diagnostics.filter((entry) =>
        entry.code.includes("session_relationship"),
      ),
    ).toEqual([]);
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ code: "missing_tool_result" }),
    );
  });
});
