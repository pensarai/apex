import { generateText, jsonSchema, tool } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getVisiblePickerModels } from "../../../tui/components/model-picker/model-visibility";
import { resolveExplicitCliModel } from "../../cli/model";
import { getAvailableModels } from "../../providers/utils";
import { buildReasoningProviderOptions, modelRequiresThinking } from "../ai";
import { getMaxOutputTokens, getModelInfo } from "../models";
import { getProviderModel } from "../utils";

const models = [
  { slug: "claude-fable-5", profiles: ["us", "global"], required: true },
];
const routes = models.flatMap(({ slug, profiles, required }) =>
  profiles.map((profile) => ({ id: `${profile}.anthropic.${slug}`, required })),
);

afterEach(() => vi.unstubAllGlobals());

describe.each(routes)("Bedrock $id", ({ id, required }) => {
  it("selects the documented inference profile with the full context and output limits", () => {
    expect(getModelInfo(id)).toMatchObject({
      provider: "bedrock",
      contextLength: 1_000_000,
    });
    const models = getVisiblePickerModels(
      getAvailableModels({
        responsibleUseAccepted: true,
        bedrockAPIKey: "test-key",
      }),
    );
    expect(models.some((model) => model.id === id)).toBe(true);
    expect(resolveExplicitCliModel({ model: id })).toBe(id);
    expect(getMaxOutputTokens(id)).toBe(128_000);
    expect(modelRequiresThinking(id)).toBe(required);
  });

  it("uses Converse tools and preserves signed thinking across a tool round trip", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        Response.json({
          output: {
            message: {
              role: "assistant",
              content: [
                {
                  reasoningContent: {
                    reasoningText: {
                      text: "Checking",
                      signature: "signed-context",
                    },
                  },
                },
                {
                  toolUse: { toolUseId: "call_test", name: "check", input: {} },
                },
              ],
            },
          },
          stopReason: "tool_use",
          usage: { inputTokens: 12, outputTokens: 8, totalTokens: 20 },
          metrics: { latencyMs: 1 },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const options = {
      model: getProviderModel(id, {
        bedrock: { apiKey: "test-key", region: "us-east-1" },
      }),
      tools: {
        check: tool({
          inputSchema: jsonSchema({
            type: "object",
            properties: {},
            additionalProperties: false,
          }),
        }),
      },
      providerOptions: buildReasoningProviderOptions(id, {
        enableThinking: true,
        thinkingEffort: "high",
      }),
      maxOutputTokens: getMaxOutputTokens(id),
    };
    const first = await generateText({ ...options, prompt: "Check" });
    expect(first.toolCalls).toMatchObject([
      { toolName: "check", toolCallId: "call_test" },
    ]);
    await generateText({
      ...options,
      messages: [
        { role: "user", content: "Check" },
        ...first.response.messages,
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolName: "check",
              toolCallId: "call_test",
              output: { type: "json", value: { ok: true } },
            },
          ],
        },
      ],
    });
    const call = fetchMock.mock.calls[1];
    if (!call) throw new Error("Expected Bedrock follow-up");
    expect(String(call[0])).toBe(
      `https://bedrock-runtime.us-east-1.amazonaws.com/model/${encodeURIComponent(id)}/converse`,
    );
    const body = JSON.parse(String(call[1]?.body));
    expect(body).toMatchObject({
      inferenceConfig: { maxTokens: 128_000 },
      additionalModelRequestFields: {
        thinking: { type: "adaptive", display: "summarized" },
        output_config: { effort: "high" },
      },
    });
    expect(body.toolConfig.tools).toContainEqual(
      expect.objectContaining({
        toolSpec: expect.objectContaining({ name: "check" }),
      }),
    );
    expect(body.messages).toContainEqual(
      expect.objectContaining({
        role: "assistant",
        content: expect.arrayContaining([
          {
            reasoningContent: {
              reasoningText: { text: "Checking", signature: "signed-context" },
            },
          },
        ]),
      }),
    );
    expect(body.messages).toContainEqual(
      expect.objectContaining({
        role: "user",
        content: expect.arrayContaining([
          expect.objectContaining({
            toolResult: expect.objectContaining({ toolUseId: "call_test" }),
          }),
        ]),
      }),
    );
  });

  it("keeps mandatory thinking enabled when the caller disables it", () => {
    const options = buildReasoningProviderOptions(id, {
      enableThinking: false,
    });
    if (required)
      expect(options?.bedrock?.reasoningConfig?.type).toBe("adaptive");
    else
      expect(
        options?.bedrock?.additionalModelRequestFields?.thinking.type,
      ).toBe("disabled");
  });
});
