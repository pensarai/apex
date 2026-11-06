import type {
  LanguageModelV3CallOptions,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { stepCountIs } from "ai";
import { afterEach, expect, it, vi } from "vitest";
import { z } from "zod";
import { type StreamResponseOpts, streamResponse } from "./ai";

const telemetry = vi.hoisted(() => vi.fn());
vi.mock("../observability", async (original) => ({
  ...(await original<typeof import("../observability")>()),
  createAiTelemetrySettings: (options: unknown) => {
    telemetry(options);
    return { isEnabled: false };
  },
}));
const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};
const opus = "global.anthropic.claude-opus-4-6-v1";
afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});
async function fixture(
  options: Partial<StreamResponseOpts> = {},
  outcome: "wire" | "valid" | "invalid" | "throw" = "valid",
) {
  const primary: LanguageModelV3CallOptions[] = [],
    repairs: LanguageModelV3CallOptions[] = [];
  const execute = vi.fn(async () => "ok");
  const result = streamResponse({
    model: opus,
    reasoning: "high",
    silent: true,
    prompt: "Synthetic fixture",
    stopWhen: stepCountIs(2),
    authConfig: {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
      anthropicAPIKey: "test",
      openAiAPIKey: "test",
      openRouterAPIKey: "test",
    },
    ...options,
    tools: {
      fixture: { inputSchema: z.object({ body: z.string() }), execute },
    },
    languageModelMiddleware: {
      specificationVersion: "v3",
      wrapStream: async ({ params }) => {
        primary.push(params);
        const parts: LanguageModelV3StreamPart[] =
          primary.length === 1
            ? [
                {
                  type: "tool-call",
                  toolCallId: "fixture",
                  toolName: "fixture",
                  input: '{"body":{"synthetic":true}}',
                },
              ]
            : [];
        parts.push({
          type: "finish",
          finishReason: {
            unified: primary.length === 1 ? "tool-calls" : "stop",
            raw: undefined,
          },
          usage,
        });
        return {
          stream: new ReadableStream({
            start(c) {
              for (const p of parts) c.enqueue(p);
              c.close();
            },
          }),
        };
      },
      wrapGenerate: async ({ params, doGenerate }) => {
        repairs.push(params);
        if (outcome === "wire") return doGenerate();
        if (outcome === "throw") throw new Error("synthetic provider failure");
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                outcome === "invalid" ? { body: {} } : { body: "synthetic" },
              ),
            },
          ],
          finishReason: { unified: "stop", raw: undefined },
          usage,
          warnings: [],
        };
      },
    },
  });
  const kinds: string[] = [];
  for await (const p of result.fullStream) kinds.push(p.type);
  await result.text;
  return { primary, repairs, execute, kinds };
}
it("keeps primary adaptive reasoning while actual Bedrock repair uses the same schema via forced JSON", async () => {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json({
        output: {
          message: {
            role: "assistant",
            content: [
              {
                toolUse: {
                  toolUseId: "json-1",
                  name: "json",
                  input: { body: "synthetic" },
                },
              },
            ],
          },
        },
        stopReason: "tool_use",
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
      }),
  );
  vi.stubGlobal("fetch", fetchMock);
  const f = await fixture({}, "wire");
  expect(f.execute).toHaveBeenCalledTimes(1);
  expect(f.primary[0].providerOptions?.bedrock).toMatchObject({
    reasoningConfig: { type: "adaptive", maxReasoningEffort: "high" },
  });
  const call = fetchMock.mock.calls[0];
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(String(call[0])).toContain(opus);
  const body = JSON.parse(String(call[1]?.body));
  expect(body.additionalModelRequestFields).toEqual({
    thinking: { type: "disabled" },
  });
  expect(body.inferenceConfig.maxTokens).toBe(128000);
  expect(body.toolConfig.toolChoice).toEqual({ any: {} });
  expect(body.toolConfig.tools[0].toolSpec.inputSchema.json).toMatchObject({
    type: "object",
    required: ["body"],
    properties: { body: { type: "string" } },
  });
  expect(f.repairs[0].providerOptions?.pensarRuntime).toEqual({
    ephemeral: true,
  });
  const repairTelemetry = telemetry.mock.calls.find(
    ([value]) => value.operation === "apex.tool.repair",
  )?.[0];
  expect(repairTelemetry.reasoning.requested).toBe("disabled");
  const { pensarRuntime: _ephemeral, ...repairReasoning } =
    f.repairs[0].providerOptions ?? {};
  expect(JSON.parse(repairTelemetry.reasoning.parameters)).toEqual(
    repairReasoning,
  );
  const primaryTelemetry = telemetry.mock.calls.find(
    ([value]) => value.operation === "apex.agent.stream",
  )?.[0];
  expect(primaryTelemetry.reasoning.requested).toBe("high");
  expect(JSON.parse(primaryTelemetry.reasoning.parameters)).toEqual(
    f.primary[0].providerOptions,
  );
});
it.each([
  "invalid",
  "throw",
] as const)("preserves %s repair failure without executing tools", async (outcome) => {
  const f = await fixture({}, outcome);
  expect(f.execute).not.toHaveBeenCalled();
  expect(f.kinds).toContain("tool-error");
  expect(f.primary).toHaveLength(2);
});
it("also overrides legacy enabled thinking without retaining effort", async () => {
  const f = await fixture({
    reasoning: undefined,
    enableThinking: true,
    thinkingEffort: "high",
  });
  expect(f.repairs[0].providerOptions?.anthropic).toEqual({
    thinking: { type: "disabled" },
  });
  expect(f.repairs[0].providerOptions?.bedrock).toEqual({
    reasoningConfig: { type: "disabled" },
    additionalModelRequestFields: { thinking: { type: "disabled" } },
  });
});
it.each([
  {
    model: "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    reasoning: "enabled" as const,
    disabled: true,
  },
  { model: opus, reasoning: "disabled" as const, disabled: true },
  {
    model: "global.anthropic.claude-opus-5-5",
    reasoning: "default" as const,
    disabled: false,
  },
  {
    model: "global.anthropic.claude-3-haiku-20240307-v1:0",
    reasoning: "default" as const,
    disabled: false,
  },
  { model: "claude-opus-5-5", reasoning: "high" as const, disabled: false },
  { model: "claude-opus-4-6", reasoning: "high" as const, disabled: false },
  { model: "gpt-5", reasoning: "high" as const, disabled: false },
  {
    model: "anthropic/claude-opus-4.6",
    reasoning: "high" as const,
    disabled: false,
  },
])("respects capabilities for $model/$reasoning", async ({
  model,
  reasoning,
  disabled,
}) => {
  const f = await fixture({ model, reasoning });
  if (disabled)
    expect(f.repairs[0].providerOptions?.bedrock).toMatchObject({
      reasoningConfig: { type: "disabled" },
    });
  else {
    const { pensarRuntime: _, ...actual } = f.repairs[0].providerOptions ?? {};
    expect(actual).toEqual(f.primary[0].providerOptions ?? {});
  }
});
