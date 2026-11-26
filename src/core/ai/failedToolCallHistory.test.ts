import {
  generateText,
  type ModelMessage,
  NoSuchToolError,
  stepCountIs,
  tool,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { projectFailedToolCalls } from "./failedToolCallHistory";

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};
const bad = 'unknown" tool';
const errorOutput = {
  type: "error-text" as const,
  value: "unknown tool was rejected",
};
function history(): ModelMessage[] {
  return [
    {
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolCallId: "bad",
          toolName: bad,
          input: { intent: "synthetic" },
        },
      ],
    },
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "bad",
          toolName: bad,
          output: errorOutput,
        },
      ],
    },
  ];
}
const rejected = [
  {
    toolCallId: "bad",
    toolName: bad,
    error: new NoSuchToolError({ toolName: bad }),
  },
];

describe("failed tool-call provider view", () => {
  it("keeps historical errors untouched without an actual NoSuchToolError receipt", () => {
    const messages = history();
    expect(projectFailedToolCalls(messages, [])).toBe(messages);
    expect(
      projectFailedToolCalls(messages, [
        {
          toolCallId: "bad",
          toolName: bad,
          error: new Error("execution failed"),
        },
      ]),
    ).toBe(messages);
  });
  it("requires both matching call and failed result rather than dropping partial or mismatched history", () => {
    const messages = history();
    expect(projectFailedToolCalls(messages.slice(0, 1), rejected)).toEqual(
      messages.slice(0, 1),
    );
    expect(
      projectFailedToolCalls(messages, [{ ...rejected[0], toolName: "other" }]),
    ).toBe(messages);
    const success: ModelMessage[] = [
      messages[0],
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "bad",
            toolName: bad,
            output: { type: "text", value: "not a failure" },
          },
        ],
      },
    ];
    expect(projectFailedToolCalls(success, rejected)).toBe(success);
  });
  it("preserves original evidence without mutating source messages or adding native tool calls", () => {
    const messages = history(),
      original = structuredClone(messages);
    const projected = projectFailedToolCalls(messages, rejected);
    expect(messages).toEqual(original);
    expect(projected.map((message) => message.role)).toEqual([
      "assistant",
      "user",
    ]);
    expect(JSON.stringify(projected)).toContain("synthetic");
    expect(JSON.stringify(projected)).toContain(errorOutput.value);
    expect(projectFailedToolCalls(projected, rejected)).toBe(projected);
  });
  it("fails an inconsistent approval of a confirmed failed unknown call rather than dropping it", () => {
    const messages = history();
    if (
      messages[0].role !== "assistant" ||
      typeof messages[0].content === "string"
    )
      throw new Error("expected assistant parts");
    messages[0].content.push({
      type: "tool-approval-request",
      approvalId: "inconsistent",
      toolCallId: "bad",
    });
    expect(() => projectFailedToolCalls(messages, rejected)).toThrow(
      "unexpectedly has an approval request",
    );
  });
  it("preserves a trailing native approval response and executes only that approved known call through the real SDK", async () => {
    const execute = vi.fn(async () => "approved effect");
    const tools = {
      approved_tool: tool({
        inputSchema: z.object({}),
        needsApproval: true,
        execute,
      }),
    };
    const first = await generateText({
      model: new MockLanguageModelV3({
        doGenerate: async () => ({
          content: [
            {
              type: "tool-call",
              toolCallId: "approved-call",
              toolName: "approved_tool",
              input: "{}",
            },
            {
              type: "tool-call",
              toolCallId: "bad",
              toolName: bad,
              input: "{}",
            },
          ],
          finishReason: { unified: "tool-calls", raw: "tool_use" },
          usage,
          warnings: [],
        }),
      }),
      tools,
      prompt: "Synthetic approval and rejected parallel call",
      stopWhen: stepCountIs(1),
      experimental_repairToolCall: async () => null,
    });
    expect(execute).not.toHaveBeenCalled();
    const messages: ModelMessage[] = [
      {
        role: "user",
        content: "Synthetic approval and rejected parallel call",
      },
      ...first.response.messages,
    ];
    const request = messages.flatMap((message) =>
      message.role === "assistant" && Array.isArray(message.content)
        ? message.content.filter(
            (part) => part.type === "tool-approval-request",
          )
        : [],
    )[0];
    if (!request || request.type !== "tool-approval-request")
      throw new Error("missing actual SDK approval request");
    const last = messages.at(-1);
    if (last?.role !== "tool")
      throw new Error("missing failed tool-result message");
    const approval = {
      type: "tool-approval-response" as const,
      approvalId: request.approvalId,
      approved: true,
    };
    last.content.push(approval);
    const original = structuredClone(messages);
    const failed = first.steps[0].toolCalls.find(
      (call) => call.toolCallId === "bad",
    );
    if (!failed || !failed.dynamic || !failed.invalid)
      throw new Error("missing actual SDK unknown-tool receipt");
    expect(NoSuchToolError.isInstance(failed.error)).toBe(true);
    const projected = projectFailedToolCalls(messages, [failed]);
    expect(messages).toEqual(original);
    expect(projected.at(-1)).toEqual({ role: "tool", content: [approval] });
    expect(JSON.stringify(projected)).toContain(request.approvalId);
    const providerCalls = vi.fn();
    const resumed = await generateText({
      model: new MockLanguageModelV3({
        doGenerate: async ({ prompt }) => {
          providerCalls(prompt);
          expect(
            prompt
              .flatMap((message) =>
                message.role === "assistant"
                  ? message.content.filter((part) => part.type === "tool-call")
                  : [],
              )
              .some((part) => part.toolName === bad),
          ).toBe(false);
          return {
            content: [{ type: "text", text: "approval replay complete" }],
            finishReason: { unified: "stop", raw: "stop" },
            usage,
            warnings: [],
          };
        },
      }),
      tools,
      messages: projected,
      stopWhen: stepCountIs(1),
    });
    expect(execute).toHaveBeenCalledTimes(1);
    expect(providerCalls).toHaveBeenCalledTimes(1);
    expect(resumed.text).toBe("approval replay complete");
  });
});
