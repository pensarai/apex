import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { describe, expect, it } from "vitest";
import { parseResponsesSSE } from "./pensarResponsesStream";

function sseStreamFrom(events: Array<{ event: string; data: unknown }>) {
  const text = events
    .map((e) => `event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`)
    .join("");
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

async function collect(
  stream: ReadableStream<LanguageModelV3StreamPart>,
): Promise<LanguageModelV3StreamPart[]> {
  const parts: LanguageModelV3StreamPart[] = [];
  const reader = stream.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return parts;
}

describe("parseResponsesSSE", () => {
  it("parses text, tool calls, and final usage from Responses events", async () => {
    const sse = sseStreamFrom([
      {
        event: "response.output_item.added",
        data: {
          type: "response.output_item.added",
          item: { id: "item_1", type: "message" },
        },
      },
      {
        event: "response.output_text.delta",
        data: {
          type: "response.output_text.delta",
          item_id: "item_1",
          content_index: 0,
          delta: "Hello",
        },
      },
      {
        event: "response.output_text.delta",
        data: {
          type: "response.output_text.delta",
          item_id: "item_1",
          content_index: 0,
          delta: " world",
        },
      },
      {
        event: "response.output_text.done",
        data: {
          type: "response.output_text.done",
          item_id: "item_1",
          content_index: 0,
        },
      },
      {
        event: "response.output_item.added",
        data: {
          type: "response.output_item.added",
          item: { id: "fc_1", type: "function_call", call_id: "call_abc", name: "run_tool" },
        },
      },
      {
        event: "response.function_call_arguments.delta",
        data: {
          type: "response.function_call_arguments.delta",
          item_id: "fc_1",
          delta: '{"x":1}',
        },
      },
      {
        event: "response.output_item.done",
        data: {
          type: "response.output_item.done",
          item: {
            id: "fc_1",
            type: "function_call",
            call_id: "call_abc",
            name: "run_tool",
            arguments: '{"x":1}',
          },
        },
      },
      {
        event: "response.completed",
        data: {
          type: "response.completed",
          response: {
            status: "completed",
            usage: { input_tokens: 11, output_tokens: 22 },
          },
        },
      },
    ]);

    const parts = await collect(
      parseResponsesSSE(sse, { idleTimeoutMs: 5_000 }),
    );
    const types = parts.map((p) => p.type);

    expect(types[0]).toBe("stream-start");
    expect(types).toContain("text-start");
    expect(types).toContain("text-end");

    const text = parts
      .filter((p): p is Extract<LanguageModelV3StreamPart, { type: "text-delta" }> =>
        p.type === "text-delta",
      )
      .map((p) => p.delta)
      .join("");
    expect(text).toBe("Hello world");

    const toolCall = parts.find(
      (p): p is Extract<LanguageModelV3StreamPart, { type: "tool-call" }> =>
        p.type === "tool-call",
    );
    expect(toolCall?.toolCallId).toBe("call_abc");
    expect(toolCall?.toolName).toBe("run_tool");
    expect(toolCall?.input).toBe('{"x":1}');

    const finish = parts.find(
      (p): p is Extract<LanguageModelV3StreamPart, { type: "finish" }> =>
        p.type === "finish",
    );
    expect(finish?.finishReason.unified).toBe("tool-calls");
    expect(finish?.usage.inputTokens.total).toBe(11);
    expect(finish?.usage.outputTokens.total).toBe(22);
  });

  it("does not double-count cached input tokens", async () => {
    const sse = sseStreamFrom([
      {
        event: "response.completed",
        data: {
          type: "response.completed",
          response: {
            status: "completed",
            usage: {
              input_tokens: 100,
              input_tokens_details: { cached_tokens: 40 },
              output_tokens: 12,
            },
          },
        },
      },
    ]);

    const parts = await collect(
      parseResponsesSSE(sse, { idleTimeoutMs: 5_000 }),
    );
    const finish = parts.find(
      (p): p is Extract<LanguageModelV3StreamPart, { type: "finish" }> =>
        p.type === "finish",
    );

    expect(finish?.usage.inputTokens.total).toBe(100);
    expect(finish?.usage.inputTokens.noCache).toBe(60);
    expect(finish?.usage.inputTokens.cacheRead).toBe(40);
    expect(finish?.usage.outputTokens.total).toBe(12);
  });

  it("surfaces upstream error events", async () => {
    const sse = sseStreamFrom([
      {
        event: "error",
        data: { type: "error", error: { message: "boom" } },
      },
    ]);
    const reader = parseResponsesSSE(sse, { idleTimeoutMs: 5_000 }).getReader();
    // stream-start is enqueued first, then the error surfaces.
    await reader.read();
    await expect(reader.read()).rejects.toThrow("boom");
  });
});
