import { posix } from "node:path";
import type { LanguageModelV3ToolApprovalRequest } from "@ai-sdk/provider";
import { describe, expect, it } from "vitest";
import type { JsonValue } from "../ai/native-rollout-evidence";
import { convertNativeRolloutSourcesToAtif } from "./convert";
import { serializeAtifExportBundle } from "./serialize";
import { defaultPrompt, lookupTool, nativeSource } from "./test-fixtures";

const identity = {
  agent: { name: "apex", version: "test" },
  exporter: { name: "apex-native-evidence", version: "1" },
};

describe("native rollout evidence to ATIF conversion", () => {
  it.each([
    42,
    { text: "invented" },
  ])("diagnoses malformed reasoning delta %j without inventing output", (delta) => {
    const source = nativeSource({
      normalizedOutput: {
        parts: [{ type: "reasoning-delta", id: "r", delta }],
      },
    });
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    expect(
      bundle.documents.ses_fixture?.[0]?.steps.at(-1)?.reasoning_content,
    ).toBeUndefined();
    expect(bundle.manifest.completeness.status).toBe("partial");
    expect(bundle.manifest.completeness.diagnostics).toContainEqual(
      expect.objectContaining({ code: "invalid_content_part" }),
    );
  });

  it("preserves model-visible function tool settings in versioned agent metadata", () => {
    const settings = {
      strict: true,
      inputExamples: [{ input: { id: "example" } }],
      providerOptions: { fixture: { cache: "enabled" } },
    };
    const source = nativeSource({
      tools: [
        {
          type: "function",
          name: "lookup",
          inputSchema: { type: "object" },
          ...settings,
        },
      ],
    });
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    expect(
      bundle.documents.ses_fixture?.[0]?.agent.extra?.apex_tool_settings,
    ).toEqual({
      version: 1,
      tools: [{ index: 0, name: "lookup", ...settings }],
    });
    expect(bundle.manifest.completeness.status).toBe("complete");
  });

  it.each([
    "same-session",
    "other-session",
    "copied-result",
  ])("does not let a later %s result satisfy an earlier reused call id", (mode) => {
    const call = {
      type: "tool-call",
      toolCallId: "call_reused",
      toolName: "lookup",
      input: {},
    };
    const result = {
      type: "tool-result",
      toolCallId: "call_reused",
      output: { type: "text", value: "second result" },
    };
    const first = nativeSource({
      id: "first",
      attemptId: "atm_first",
      outputContent: [call],
    });
    const second = nativeSource({
      id: "second",
      attemptId: "atm_second",
      turnIndex: 2,
      sessionId: mode === "other-session" ? "ses_other" : "ses_fixture",
      outputContent: mode === "copied-result" ? [call] : [call, result],
    });
    const third = nativeSource({
      id: "third",
      attemptId: "atm_third",
      turnIndex: 3,
      prompt: [
        ...defaultPrompt,
        { role: "assistant", content: [call] },
        { role: "tool", content: [result] },
      ],
    });
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources:
        mode === "copied-result" ? [first, second, third] : [first, second],
      rootSourceId: first.id,
    });
    expect(bundle.manifest.completeness.status).toBe("partial");
    expect(bundle.manifest.completeness.diagnostics).toContainEqual(
      expect.objectContaining({
        code: "missing_tool_result",
        path: "atif_atm_first",
      }),
    );
    if (mode !== "other-session")
      expect(bundle.manifest.completeness.diagnostics).toContainEqual(
        expect.objectContaining({ code: "reused_tool_call_id" }),
      );
  });

  it.each([
    "output",
    "prompt",
  ])("maps %s tool-result media to exact binary assets", (location) => {
    const png = Buffer.from("fixture-png");
    const audio = Buffer.from("fixture-audio");
    const contentParts: JsonValue[] = [
      {
        type: "tool-call",
        toolCallId: "media",
        toolName: "lookup",
        input: {},
      },
      {
        type: "tool-result",
        toolCallId: "media",
        output: {
          type: "content",
          value: [
            { type: "text", text: "media result" },
            {
              type: "image-data",
              data: png.toString("base64"),
              mediaType: "image/png",
            },
            {
              type: "file-data",
              data: audio.toString("base64"),
              mediaType: "audio/wav",
            },
          ],
        },
      },
    ];
    const source = nativeSource(
      location === "output"
        ? { outputContent: contentParts }
        : {
            prompt: [
              ...defaultPrompt,
              { role: "assistant", content: [contentParts[0]] },
              { role: "tool", content: [contentParts[1]] },
            ],
          },
    );
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    const content = bundle.documents.ses_fixture?.[0]?.steps.find(
      (step) => step.observation,
    )?.observation?.results[0]?.content;
    expect(content).toEqual([
      { type: "text", text: "media result" },
      {
        type: "image",
        source: { media_type: "image/png", path: expect.any(String) },
      },
      {
        type: "audio",
        source: { media_type: "audio/wav", path: expect.any(String) },
      },
    ]);
    expect(
      bundle.files
        .filter((file) => ["image/png", "audio/wav"].includes(file.mediaType))
        .map((file) => Buffer.from(file.bytes).toString())
        .sort(),
    ).toEqual(["fixture-audio", "fixture-png"]);
    expect(bundle.manifest.completeness.status).toBe("complete");
  });

  it("diagnoses unsupported tool-result content", () => {
    const source = nativeSource({
      outputContent: [
        { type: "tool-call", toolCallId: "pdf", toolName: "lookup", input: {} },
        {
          type: "tool-result",
          toolCallId: "pdf",
          output: {
            type: "content",
            value: [
              { type: "file-data", data: "cGRm", mediaType: "application/pdf" },
            ],
          },
        },
      ],
    });
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    expect(bundle.manifest.completeness.status).toBe("partial");
    expect(bundle.manifest.completeness.diagnostics).toContainEqual(
      expect.objectContaining({ code: "unsupported_media_type" }),
    );
  });

  it("states that completeness covers supplied evidence rather than the entire run", () => {
    const source = nativeSource();
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });
    expect(bundle.manifest.completeness.status).toBe("complete");
    expect(bundle.manifest.completeness.diagnostics).toContainEqual(
      expect.objectContaining({
        code: "source_relative_completeness",
        message: expect.stringContaining("capture report"),
      }),
    );
  });

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
      continued_trajectory_ref: "atif_atm_turn_2.json",
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

    expect(image?.source.path).toMatch(/^\.\.\/assets\/[a-f0-9]{64}$/);
    expect(
      result.files.some(
        (file) =>
          file.kind === "asset" &&
          file.path ===
            posix.normalize(
              posix.join("trajectories", image?.source.path ?? ""),
            ) &&
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
          path: expect.stringMatching(/^\.\.\/assets\/[a-f0-9]{64}$/),
        },
      },
      { type: "text", text: "after" },
    ]);
  });

  it("marks a numeric text delta as partial without inventing text or losing source bytes", () => {
    const source = nativeSource({
      normalizedOutput: {
        parts: [{ type: "text-delta", id: "fixture-text", delta: 42 }],
      },
    });
    const originalBytes = Buffer.from(source.bytes);

    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(bundle.manifest.validation.status).toBe("valid");
    expect(bundle.manifest.completeness.status).toBe("partial");
    expect(bundle.manifest.completeness.diagnostics).toContainEqual(
      expect.objectContaining({
        code: "invalid_content_part",
        severity: "warning",
        sourceId: source.id,
        path: "output.parts[0]",
      }),
    );
    expect(bundle.documents.ses_fixture?.[0]?.steps.at(-1)?.message).toBe("");
    expect(bundle.files.find((file) => file.kind === "source")?.bytes).toEqual(
      originalBytes,
    );
    expect(source.bytes).toEqual(originalBytes);
  });

  it("marks an unsupported SDK tool approval as partial and retains exact source bytes", () => {
    const approval = {
      type: "tool-approval-request",
      approvalId: "approval-fixture",
      toolCallId: "call-fixture",
    } satisfies LanguageModelV3ToolApprovalRequest;
    const source = nativeSource({ normalizedOutput: { parts: [approval] } });
    const originalBytes = Buffer.from(source.bytes);

    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(bundle.manifest.validation.status).toBe("valid");
    expect(bundle.manifest.completeness.status).toBe("partial");
    expect(bundle.manifest.completeness.diagnostics).toContainEqual(
      expect.objectContaining({
        code: "unsupported_content_part",
        severity: "warning",
        sourceId: source.id,
        path: "output.parts[0]",
      }),
    );
    expect(bundle.documents.ses_fixture?.[0]?.steps.at(-1)?.message).toBe("");
    expect(bundle.files.find((file) => file.kind === "source")?.bytes).toEqual(
      originalBytes,
    );
    expect(source.bytes).toEqual(originalBytes);
  });

  it("keeps benign stream controls complete and preserves text, reasoning and usage", () => {
    const source = nativeSource({
      normalizedOutput: {
        parts: [
          { type: "stream-start", warnings: [] },
          { type: "response-metadata", id: "response-fixture" },
          { type: "raw", rawValue: { transport: "synthetic" } },
          { type: "text-start", id: "fixture-text" },
          { type: "text-delta", id: "fixture-text", delta: "blue" },
          { type: "text-end", id: "fixture-text" },
          { type: "reasoning-start", id: "fixture-reasoning" },
          {
            type: "reasoning-delta",
            id: "fixture-reasoning",
            delta: "A color.",
          },
          { type: "reasoning-end", id: "fixture-reasoning" },
          { type: "tool-input-end", id: "fixture-control" },
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
    const originalBytes = Buffer.from(source.bytes);

    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(bundle.manifest.validation.status).toBe("valid");
    expect(bundle.manifest.completeness.status).toBe("complete");
    expect(bundle.manifest.validation.diagnostics).toEqual([]);
    expect(bundle.documents.ses_fixture?.[0]?.steps.at(-1)).toMatchObject({
      message: "blue",
      reasoning_content: "A color.",
      metrics: { prompt_tokens: 12, cached_tokens: 2, completion_tokens: 4 },
    });
    expect(bundle.files.find((file) => file.kind === "source")?.bytes).toEqual(
      originalBytes,
    );
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
        trajectory_path: "atif_atm_child.json",
        session_id: "ses-child",
      },
      {
        trajectory_id: "atif_atm_grandchild",
        trajectory_path: "atif_atm_grandchild.json",
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
