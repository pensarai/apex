import type { LanguageModelV3CallOptions } from "@ai-sdk/provider";
import { describe, expect, it } from "vitest";
import { convertToBedrockFormat } from "./pensarFormatters";

function baseOptions(
  overrides: Partial<LanguageModelV3CallOptions> = {},
): LanguageModelV3CallOptions {
  return {
    prompt: [
      { role: "system", content: "You are a pentester." },
      { role: "user", content: [{ type: "text", text: "Scan this." }] },
    ],
    ...overrides,
  } as unknown as LanguageModelV3CallOptions;
}

describe("convertToBedrockFormat → Responses API (GPT 5.5)", () => {
  it("maps system to instructions and user to typed input", () => {
    const body = convertToBedrockFormat("openai.gpt-5.5", baseOptions());
    expect(body.instructions).toBe("You are a pentester.");
    expect(body.stream).toBe(true);
    expect(body.max_output_tokens).toBe(128000);
    expect(body.input).toEqual([
      { role: "user", content: [{ type: "input_text", text: "Scan this." }] },
    ]);
    // Must NOT produce an Anthropic-shaped body.
    expect(body.anthropic_version).toBeUndefined();
    expect(body.messages).toBeUndefined();
  });

  it("maps assistant tool calls and tool results to Responses items", () => {
    const options = baseOptions({
      prompt: [
        { role: "user", content: [{ type: "text", text: "go" }] },
        {
          role: "assistant",
          content: [
            { type: "text", text: "calling" },
            {
              type: "tool-call",
              toolCallId: "call_1",
              toolName: "http_get",
              input: { url: "https://x" },
            },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "call_1",
              toolName: "http_get",
              output: { type: "text", value: "200 OK" },
            },
          ],
        },
      ] as unknown as LanguageModelV3CallOptions["prompt"],
    });

    const body = convertToBedrockFormat("openai.gpt-5.5", options);
    const input = body.input as Array<Record<string, unknown>>;

    expect(input).toContainEqual({
      role: "assistant",
      content: [{ type: "output_text", text: "calling" }],
    });
    expect(input).toContainEqual({
      type: "function_call",
      call_id: "call_1",
      name: "http_get",
      arguments: JSON.stringify({ url: "https://x" }),
    });
    expect(input).toContainEqual({
      type: "function_call_output",
      call_id: "call_1",
      output: "200 OK",
    });
  });

  it("converts tools and tool_choice to the Responses shape", () => {
    const options = baseOptions({
      tools: [
        {
          type: "function",
          name: "http_get",
          description: "fetch",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      toolChoice: { type: "required" },
    } as unknown as Partial<LanguageModelV3CallOptions>);

    const body = convertToBedrockFormat("openai.gpt-5.5", options);
    expect(body.tools).toEqual([
      {
        type: "function",
        name: "http_get",
        description: "fetch",
        parameters: { type: "object", properties: {} },
      },
    ]);
    expect(body.tool_choice).toBe("required");
  });

  it("still produces an Anthropic body for Claude models", () => {
    const body = convertToBedrockFormat(
      "anthropic.claude-opus-4-6-v1",
      baseOptions(),
    );
    expect(body.anthropic_version).toBe("bedrock-2023-05-31");
    expect(Array.isArray(body.messages)).toBe(true);
  });
});
