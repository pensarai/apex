import type {
  LanguageModelV3FinishReason,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { describe, expect, it } from "vitest";
import { withCutOffToolCallGuard } from "./cutOffToolCalls";

const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

const truncatedRm: LanguageModelV3StreamPart = {
  type: "tool-call",
  toolCallId: "call-1",
  toolName: "execute_command",
  input: JSON.stringify({ command: "rm -rf /tmp" }),
};

const finish = (
  unified: LanguageModelV3FinishReason["unified"],
): LanguageModelV3StreamPart => ({
  type: "finish",
  finishReason: { unified, raw: unified },
  usage,
});

async function streamed(
  chunks: LanguageModelV3StreamPart[],
): Promise<LanguageModelV3StreamPart[]> {
  const model = withCutOffToolCallGuard(
    new MockLanguageModelV3({
      doStream: async () => ({ stream: simulateReadableStream({ chunks }) }),
    }),
  );
  const { stream } = await model.doStream({} as never);
  const parts: LanguageModelV3StreamPart[] = [];
  for await (const part of stream as unknown as AsyncIterable<LanguageModelV3StreamPart>)
    parts.push(part);
  return parts;
}

describe("withCutOffToolCallGuard", () => {
  it("drops a tool call when the provider's content filter cut the response off", async () => {
    const parts = await streamed([truncatedRm, finish("content-filter")]);
    expect(parts.map((p) => p.type)).toEqual(["finish"]);
  });

  it("drops a tool call when the response hit the output token limit", async () => {
    const parts = await streamed([truncatedRm, finish("length")]);
    expect(parts.some((p) => p.type === "tool-call")).toBe(false);
  });

  it("releases tool calls, in order and before finish, when the response completed", async () => {
    const second = {
      ...truncatedRm,
      toolCallId: "call-2",
      input: '{"command":"ls"}',
    };
    const parts = await streamed([truncatedRm, second, finish("tool-calls")]);
    expect(parts).toEqual([truncatedRm, second, finish("tool-calls")]);
  });

  it("drops tool calls from a stream that ends without a finish part", async () => {
    const parts = await streamed([truncatedRm]);
    expect(parts).toEqual([]);
  });

  it("strips tool calls from a generated response that was cut off, keeping its text", async () => {
    const model = withCutOffToolCallGuard(
      new MockLanguageModelV3({
        doGenerate: async () => ({
          content: [{ type: "text", text: "Unpacking" }, truncatedRm as never],
          finishReason: { unified: "content-filter", raw: "refusal" },
          usage,
          warnings: [],
        }),
      }),
    );
    const result = await model.doGenerate({} as never);
    expect(result.content).toEqual([{ type: "text", text: "Unpacking" }]);
  });
});
