import { afterEach, describe, expect, it, vi } from "vitest";
import { buildReasoningProviderOptions, streamResponse } from "../ai";
import { getMaxOutputTokens } from "../models";
import { checkIfContextLengthError, getProviderModel } from "../utils";

function completion() {
  return Response.json({
    output: {
      message: {
        role: "assistant",
        content: [{ text: "ok" }],
      },
    },
    stopReason: "end_turn",
    usage: {
      inputTokens: 12,
      outputTokens: 2,
      totalTokens: 14,
    },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("Bedrock Claude Haiku 5.5", () => {
  it("sends adaptive max effort to the global inference profile", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => completion(),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getProviderModel("global.anthropic.claude-haiku-5-5", {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
    }).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      providerOptions: buildReasoningProviderOptions(
        "global.anthropic.claude-haiku-5-5",
        { enableThinking: true, thinkingEffort: "max" },
      ),
    });

    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Bedrock request");
    expect(String(call[0])).toContain(
      "/model/global.anthropic.claude-haiku-5-5/converse",
    );
    expect(new Headers(call[1]?.headers).get("authorization")).toBe(
      "Bearer test-key",
    );
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({
      additionalModelRequestFields: {
        thinking: { type: "adaptive", display: "summarized" },
        output_config: { effort: "max" },
      },
    });
  });

  it("forwards thinking disabled explicitly", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => completion(),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getProviderModel("global.anthropic.claude-haiku-5-5", {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
    }).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      providerOptions: buildReasoningProviderOptions(
        "global.anthropic.claude-haiku-5-5",
        { enableThinking: false },
      ),
    });

    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Bedrock request");
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({
      additionalModelRequestFields: {
        thinking: { type: "disabled" },
      },
    });
  });
});

const haiku = "global.anthropic.claude-haiku-4-5-20251001-v1:0";
const outputLimitError =
  "The maximum tokens you requested exceeds the model limit of 64000. Try again with a maximum tokens value that is lower than 64000.";

describe.each([
  "generate",
  "stream",
] as const)("Bedrock %s output reservation", (mode) => {
  it.each([
    {
      label: "Haiku model cap",
      model: haiku,
      limit: 64000,
      budget: 10000,
      expected: 64000,
    },
    {
      label: "smaller explicit total",
      model: haiku,
      limit: 16000,
      budget: 10000,
      expected: 16000,
    },
    {
      label: "SDK default answer budget",
      model: haiku,
      limit: undefined,
      budget: 10000,
      expected: 14096,
    },
    {
      label: "default bounded by Opus cap",
      model: "global.anthropic.claude-opus-4-20250514-v1:0",
      limit: undefined,
      budget: 30000,
      expected: 32000,
    },
    {
      label: "Opus model cap",
      model: "global.anthropic.claude-opus-4-20250514-v1:0",
      limit: 32000,
      budget: 10000,
      expected: 32000,
    },
  ])("keeps thinking inside $label", async ({
    model,
    limit,
    budget,
    expected,
  }) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        mode === "generate" ? completion() : new Response(new Uint8Array()),
    );
    vi.stubGlobal("fetch", fetchMock);
    const provider = getProviderModel(model, {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
    });
    const params = {
      prompt: [
        {
          role: "user" as const,
          content: [{ type: "text" as const, text: "Check" }],
        },
      ],
      maxOutputTokens: limit,
      providerOptions: {
        bedrock: { reasoningConfig: { type: "enabled", budgetTokens: budget } },
      },
    };
    if (mode === "generate") await provider.doGenerate(params);
    else {
      const result = await provider.doStream(params);
      await result.stream.cancel();
    }
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Bedrock request");
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({
      inferenceConfig: { maxTokens: expected },
      additionalModelRequestFields: {
        thinking: { type: "enabled", budget_tokens: budget },
      },
    });
    expect(expected).toBeLessThanOrEqual(getMaxOutputTokens(model));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    10000, 8000,
  ])("rejects a total limit %s that leaves no answer budget", async (limit) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const provider = getProviderModel(haiku, {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
    });
    const params = {
      prompt: [
        {
          role: "user" as const,
          content: [{ type: "text" as const, text: "Check" }],
        },
      ],
      maxOutputTokens: limit,
      providerOptions: {
        bedrock: { reasoningConfig: { type: "enabled", budgetTokens: 10000 } },
      },
    };
    await expect(
      mode === "generate"
        ? provider.doGenerate(params)
        : provider.doStream(params),
    ).rejects.toThrow("Bedrock output limit must exceed the thinking budget");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    { model: haiku, reasoningConfig: { type: "disabled" }, limit: 64000 },
    {
      model: "global.anthropic.claude-opus-4-6-v1",
      reasoningConfig: { type: "adaptive" },
      limit: 128000,
    },
    {
      model: "us.amazon.nova-pro-v1:0",
      reasoningConfig: { type: "enabled", budgetTokens: 1000 },
      limit: 4096,
    },
    { model: haiku, reasoningConfig: undefined, limit: undefined },
  ])("preserves other modes: $model $reasoningConfig", async ({
    model,
    reasoningConfig,
    limit,
  }) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        mode === "generate" ? completion() : new Response(new Uint8Array()),
    );
    vi.stubGlobal("fetch", fetchMock);
    const provider = getProviderModel(model, {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
    });
    const params = {
      prompt: [
        {
          role: "user" as const,
          content: [{ type: "text" as const, text: "Check" }],
        },
      ],
      maxOutputTokens: limit,
      providerOptions: reasoningConfig
        ? { bedrock: { reasoningConfig } }
        : undefined,
    };
    if (mode === "generate") await provider.doGenerate(params);
    else {
      const result = await provider.doStream(params);
      await result.stream.cancel();
    }
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Bedrock request");
    expect(JSON.parse(String(call[1]?.body)).inferenceConfig?.maxTokens).toBe(
      limit,
    );
  });
});

describe("Bedrock output validation recovery", () => {
  it.each([
    outputLimitError,
    "Access denied",
    "Invalid model identifier",
  ])("surfaces a nonretryable request rejection once: %s", async (message) => {
    const fetchMock = vi.fn(async () =>
      Response.json({ type: "ValidationException", message }, { status: 400 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = streamResponse({
      prompt: "Check",
      model: haiku,
      messages: [{ role: "user", content: "Check" }],
      authConfig: { bedrock: { apiKey: "test-key", region: "us-east-1" } },
      enableThinking: true,
      silent: true,
    });
    let error: unknown;
    try {
      for await (const part of result.fullStream) {
        void part;
      }
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      message: `ValidationException: ${message}`,
      statusCode: 400,
      isRetryable: false,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    "prompt is too long: 250000 tokens > 200000 maximum",
    "Your input exceeds the maximum context length",
    "Input tokens exceed the maximum token limit",
  ])("continues recognizing genuine context overflow: %s", (message) => {
    expect(checkIfContextLengthError(new Error(message))).toBe(true);
  });
});
