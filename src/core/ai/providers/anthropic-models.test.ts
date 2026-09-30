import { afterEach, describe, expect, it, vi } from "vitest";
import { getVisiblePickerModels } from "../../../tui/components/model-picker/model-visibility";
import { resolveExplicitCliModel } from "../../cli/model";
import { getAvailableModels } from "../../providers/utils";
import {
  buildReasoningProviderOptions,
  modelRequiresThinking,
  modelSupportsAdaptiveThinking,
  modelSupportsThinking,
} from "../ai";
import { getMaxOutputTokens } from "../models";
import { getProviderModel } from "../utils";

const models = [{ id: "claude-fable-5", required: true }];

function completion(model: string) {
  return Response.json({
    id: "msg_test",
    type: "message",
    role: "assistant",
    model,
    content: [{ type: "text", text: '{"ok":true}' }],
    stop_reason: "end_turn",
    stop_sequence: null,
    usage: { input_tokens: 12, output_tokens: 8 },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe.each(models)("Anthropic $id", ({ id, required }) => {
  it("exposes the model with its limits and thinking capabilities", () => {
    const available = getVisiblePickerModels(
      getAvailableModels({
        responsibleUseAccepted: true,
        anthropicAPIKey: "test-key",
      }),
    );
    expect(available.find((m) => m.id === id)).toMatchObject({
      provider: "anthropic",
      contextLength: 1_000_000,
    });
    expect(resolveExplicitCliModel({ model: id })).toBe(id);
    expect(getMaxOutputTokens(id)).toBe(128_000);
    expect(modelSupportsThinking(id)).toBe(true);
    expect(modelSupportsAdaptiveThinking(id)).toBe(true);
    expect(modelRequiresThinking(id)).toBe(required);
  });

  it.each([
    true,
    false,
  ])("sends valid structured output with thinking preference %s", async (enableThinking) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => completion(id),
    );
    vi.stubGlobal("fetch", fetchMock);
    const model = getProviderModel(id, { anthropicAPIKey: "test-key" });
    await model.doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      temperature: 0.2,
      topP: 0.9,
      topK: 10,
      responseFormat: {
        type: "json",
        schema: {
          type: "object",
          properties: { ok: { type: "boolean" } },
          required: ["ok"],
          additionalProperties: false,
        },
      },
      providerOptions: buildReasoningProviderOptions(id, {
        enableThinking,
        thinkingEffort: "medium",
      }),
    });
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Claude request");
    expect(String(call[0])).toBe("https://api.anthropic.com/v1/messages");
    const body = JSON.parse(String(call[1]?.body));
    expect(body).toMatchObject({
      model: id,
      max_tokens: 128_000,
      output_config: { effort: "medium", format: { type: "json_schema" } },
      thinking: { type: enableThinking || required ? "adaptive" : "disabled" },
    });
    expect(body.temperature).toBeUndefined();
    expect(body.top_p).toBeUndefined();
    expect(body.top_k).toBeUndefined();
    expect(body.tool_choice).toBeUndefined();
    expect(body.tools).toBeUndefined();
  });

  it("preserves signed thinking and tool calls across turns", async () => {
    const events = [
      {
        type: "message_start",
        message: {
          id: "msg_stream",
          type: "message",
          role: "assistant",
          model: id,
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 12, output_tokens: 0 },
        },
      },
      {
        type: "content_block_start",
        index: 0,
        content_block: { type: "thinking", thinking: "" },
      },
      {
        type: "content_block_delta",
        index: 0,
        delta: { type: "thinking_delta", thinking: "Check first." },
      },
      {
        type: "content_block_delta",
        index: 0,
        delta: { type: "signature_delta", signature: "test-signature" },
      },
      { type: "content_block_stop", index: 0 },
      {
        type: "content_block_start",
        index: 1,
        content_block: {
          type: "tool_use",
          id: "tool_test",
          name: "check",
          input: {},
        },
      },
      {
        type: "content_block_delta",
        index: 1,
        delta: { type: "input_json_delta", partial_json: "{}" },
      },
      { type: "content_block_stop", index: 1 },
      {
        type: "message_delta",
        delta: { stop_reason: "tool_use", stop_sequence: null },
        usage: { output_tokens: 8 },
      },
      { type: "message_stop" },
    ];
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (!JSON.parse(String(init?.body)).stream) return completion(id);
        return new Response(
          events
            .map(
              (event) =>
                `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
            )
            .join(""),
          { headers: { "content-type": "text/event-stream" } },
        );
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    const model = getProviderModel(id, { anthropicAPIKey: "test-key" });
    const { stream } = await model.doStream({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      tools: [
        {
          type: "function",
          name: "check",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      toolChoice: { type: "auto" },
    });
    const reader = stream.getReader();
    const chunks = [];
    for (let next = await reader.read(); !next.done; next = await reader.read())
      chunks.push(next.value);
    expect(chunks).toContainEqual(
      expect.objectContaining({
        type: "reasoning-delta",
        providerMetadata: { anthropic: { signature: "test-signature" } },
      }),
    );
    expect(chunks).toContainEqual(
      expect.objectContaining({
        type: "tool-call",
        toolCallId: "tool_test",
        toolName: "check",
        input: "{}",
      }),
    );
    await model.doGenerate({
      prompt: [
        { role: "user", content: [{ type: "text", text: "Check" }] },
        {
          role: "assistant",
          content: [
            {
              type: "reasoning",
              text: "Check first.",
              providerOptions: { anthropic: { signature: "test-signature" } },
            },
            {
              type: "tool-call",
              toolCallId: "tool_test",
              toolName: "check",
              input: {},
            },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "tool_test",
              toolName: "check",
              output: { type: "json", value: { ok: true } },
            },
          ],
        },
      ],
    });
    const call = fetchMock.mock.calls[1];
    if (!call) throw new Error("Expected a second Claude request");
    const body = JSON.parse(String(call[1]?.body));
    expect(body.messages[1].content).toContainEqual({
      type: "thinking",
      thinking: "Check first.",
      signature: "test-signature",
    });
    expect(body.messages[2].content).toContainEqual(
      expect.objectContaining({
        type: "tool_result",
        tool_use_id: "tool_test",
      }),
    );
  });
});
