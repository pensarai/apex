import {
  APICallError,
  type LanguageModelV4CallOptions,
  type LanguageModelV4StreamPart,
} from "@ai-sdk/provider";
import { NoSuchToolError, stepCountIs } from "ai";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { streamResponse } from "./ai";

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};
const malformedName =
  'list_memories" parameter_toolCallDescription="Synthetic request for existing memories';
async function fixture(invalidName: string, mixed = false) {
  const requests: LanguageModelV4CallOptions[] = [];
  const executions = vi.fn(async () => "known tool executed");
  const repairs = vi.fn();
  const callbackEvidence: unknown[] = [];
  const result = streamResponse({
    model: "global.anthropic.claude-opus-4-6-v1",
    prompt: "Synthetic tool-name perimeter test",
    silent: true,
    stopWhen: stepCountIs(2),
    authConfig: { bedrock: { apiKey: "synthetic-key", region: "us-east-1" } },
    tools: {
      list_memories: { inputSchema: z.object({}), execute: executions },
    },
    onStepFinish: async (step) => {
      callbackEvidence.push(step.toolCalls, step.toolResults);
    },
    languageModelMiddleware: {
      specificationVersion: "v4",
      wrapGenerate: async () => {
        repairs();
        throw new Error("unknown names have no schema to repair");
      },
      wrapStream: async ({ params }) => {
        requests.push(params);
        const badPriorNames = params.prompt.flatMap((message) =>
          message.role === "assistant"
            ? message.content.filter(
                (part) =>
                  part.type === "tool-call" &&
                  !/^[A-Za-z0-9_-]{1,64}$/.test(part.toolName),
              )
            : [],
        );
        if (badPriorNames.length)
          throw new APICallError({
            message:
              "Bedrock ValidationException: toolUse.name must match [a-zA-Z0-9_-]+ and length <=64",
            url: "https://synthetic.invalid/bedrock",
            requestBodyValues: {},
            statusCode: 400,
            isRetryable: false,
          });
        const chunks: LanguageModelV4StreamPart[] =
          requests.length === 1
            ? [
                ...(mixed
                  ? [
                      {
                        type: "tool-call" as const,
                        toolCallId: "known-call",
                        toolName: "list_memories",
                        input: "{}",
                      },
                    ]
                  : []),
                {
                  type: "tool-call",
                  toolCallId: "unknown-call",
                  toolName: invalidName,
                  input: "{}",
                },
              ]
            : [
                { type: "text-start", id: "done" },
                {
                  type: "text-delta",
                  id: "done",
                  delta: "Continuing after rejected tool call",
                },
                { type: "text-end", id: "done" },
              ];
        chunks.push({
          type: "finish",
          finishReason: {
            unified: requests.length === 1 ? "tool-calls" : "stop",
            raw: "stop",
          },
          usage,
        });
        return {
          stream: new ReadableStream({
            start(controller) {
              for (const chunk of chunks) controller.enqueue(chunk);
              controller.close();
            },
          }),
        };
      },
    },
  });
  const parts = [];
  let failure: unknown;
  try {
    for await (const part of result.fullStream) parts.push(part);
  } catch (error) {
    failure = error;
  }
  const raw = parts.find(
    (part) => part.type === "tool-call" && part.toolCallId === "unknown-call",
  );
  expect(raw).toMatchObject({
    toolName: invalidName,
    invalid: true,
    input: {},
  });
  if (!raw || raw.type !== "tool-call" || !raw.invalid)
    throw new Error("missing rejected call evidence");
  expect(NoSuchToolError.isInstance(raw.error)).toBe(true);
  expect(
    parts.some(
      (part) =>
        part.type === "tool-error" && part.toolCallId === "unknown-call",
    ),
  ).toBe(true);
  expect(JSON.stringify(callbackEvidence)).toContain(
    JSON.stringify(invalidName).slice(1, -1),
  );
  expect(repairs).not.toHaveBeenCalled();
  expect(executions).toHaveBeenCalledTimes(mixed ? 1 : 0);
  expect(requests).toHaveLength(2);
  return { requests, parts, failure, result };
}
function assertRejectedCallIsTextOnly(
  request: LanguageModelV4CallOptions,
  invalidName: string,
) {
  const nativeCalls = request.prompt.flatMap((message) =>
    message.role === "assistant"
      ? message.content.filter((part) => part.type === "tool-call")
      : [],
  );
  expect(nativeCalls.map((part) => part.toolCallId)).not.toContain(
    "unknown-call",
  );
  const nativeResults = request.prompt.flatMap((message) =>
    message.role === "tool" ? message.content : [],
  );
  expect(
    nativeResults
      .filter((part) => part.type === "tool-result")
      .map((part) => part.toolCallId),
  ).not.toContain("unknown-call");
  const text = request.prompt
    .flatMap((message) =>
      message.role === "user" || message.role === "assistant"
        ? message.content.flatMap((part) =>
            part.type === "text" ? [part.text] : [],
          )
        : [],
    )
    .join("\n");
  expect(text).toContain(JSON.stringify(invalidName));
  expect(text).toContain("unknown-call");
}

describe("unregistered tool-name continuation", () => {
  it.each([
    malformedName,
    "unknown.tool",
    "unknown_".repeat(10),
  ])("continues after an unresolved %s without sending a rejected structured name", async (invalidName) => {
    const f = await fixture(invalidName);
    assertRejectedCallIsTextOnly(f.requests[1], invalidName);
    expect(f.failure).toBeUndefined();
    expect(await f.result.text).toContain(
      "Continuing after rejected tool call",
    );
  });
  it("keeps a complete native valid pair alongside a rejected parallel call", async () => {
    const f = await fixture(malformedName, true);
    const continuation = f.requests[1].prompt;
    const calls = continuation.flatMap((message) =>
      message.role === "assistant"
        ? message.content.filter((part) => part.type === "tool-call")
        : [],
    );
    expect(calls.filter((part) => part.toolCallId === "known-call")).toEqual([
      {
        type: "tool-call",
        toolCallId: "known-call",
        toolName: "list_memories",
        input: {},
      },
    ]);
    const results = continuation.flatMap((message) =>
      message.role === "tool" ? message.content : [],
    );
    expect(
      results.filter(
        (part) =>
          part.type === "tool-result" && part.toolCallId === "known-call",
      ),
    ).toMatchObject([
      {
        type: "tool-result",
        toolCallId: "known-call",
        toolName: "list_memories",
        output: { type: "text", value: "known tool executed" },
      },
    ]);
    expect(
      continuation
        .filter((message) => message.role === "tool")
        .flatMap((message) => message.content.map((part) => part.type)),
    ).not.toContain("text");
    assertRejectedCallIsTextOnly(f.requests[1], malformedName);
    expect(f.failure).toBeUndefined();
  });
  it("treats a provider-valid but unregistered name as NoSuchToolError without guessing an executable tool", async () => {
    const f = await fixture("unknown_tool");
    expect(f.failure).toBeUndefined();
    assertRejectedCallIsTextOnly(f.requests[1], "unknown_tool");
    expect(await f.result.text).toContain(
      "Continuing after rejected tool call",
    );
  });
  it("propagates an unrelated real nonretryable provider400 without retry or tool execution", async () => {
    const provider = vi.fn();
    const originalError = new APICallError({
      message: "Invalid model configuration",
      url: "https://synthetic.invalid/bedrock",
      requestBodyValues: {},
      statusCode: 400,
      isRetryable: false,
    });
    const result = streamResponse({
      model: "global.anthropic.claude-opus-4-6-v1",
      prompt: "Synthetic unrelated provider failure",
      silent: true,
      authConfig: { bedrock: { apiKey: "synthetic-key", region: "us-east-1" } },
      languageModelMiddleware: {
        specificationVersion: "v4",
        wrapStream: async () => {
          provider();
          throw originalError;
        },
      },
    });
    const drain = async () => {
      for await (const _part of result.fullStream) {
        /* consume lifecycle */
      }
    };
    await expect(drain()).rejects.toBe(originalError);
    expect(provider).toHaveBeenCalledTimes(1);
  });
});
