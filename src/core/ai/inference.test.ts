import { type ModelMessage, stepCountIs } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { resolveExplicitCliModel } from "../cli/model";
import {
  getAvailableModels,
  getConfiguredProviders,
  getDefaultModelForConfig,
  getSavedModelForConfig,
  hasAnyProviderConfigured,
} from "../providers/utils";
import { generateObjectResponse, getContextWindow, streamResponse } from "./ai";
import { AVAILABLE_MODELS, getMaxOutputTokens, getModelInfo } from "./models";
import { getReasoningCapabilities } from "./reasoning";
import { buildAuthConfig, consumeStream, getProviderModel } from "./utils";

const upstreamId = "deepseek-v4.1-flash-1017-cyber";
const modelId = `inference:${upstreamId}`;
const authConfig = buildAuthConfig({ inferenceAPIKey: "inference-test-key" });

function completion(text: string): Response {
  return Response.json({
    id: "test",
    object: "chat.completion",
    created: 1,
    model: upstreamId,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: text },
        finish_reason: "stop",
      },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
  });
}

function sse(deltas: unknown[], finishReason = "stop"): Response {
  const chunks = deltas.map((delta) => ({
    id: "test",
    model: upstreamId,
    choices: [{ index: 0, delta, finish_reason: null as string | null }],
  }));
  chunks.push({
    id: "test",
    model: upstreamId,
    choices: [{ index: 0, delta: {}, finish_reason: finishReason }],
  });
  return new Response(
    `${chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("")}data: [DONE]\n\n`,
    { headers: { "content-type": "text/event-stream" } },
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("Inference.net provider", () => {
  it.each([
    "inference:unknown-model",
    "inference:",
    "inference:deepseek-v4.1-flash-1017-cybe",
  ])("rejects an unregistered Inference.net model before local fallback (%s)", (id) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const error = `Unknown Inference.net model "${id}". Select an available Inference.net model in /models.`;
    expect(() => getModelInfo(id)).toThrow(error);
    expect(() =>
      getProviderModel(id, {
        ...authConfig,
        local: { baseURL: "http://127.0.0.1:1234/v1" },
      }),
    ).toThrow(error);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("preserves the fallback for unregistered local model names", () => {
    expect(getModelInfo("my-local-model").provider).toBe("local");
    expect(getProviderModel("my-local-model").provider).toBe("openai.chat");
  });

  it("offers only the Cyber model with its provider-specific token limits", () => {
    const config = {
      responsibleUseAccepted: true,
      selectedModelId: modelId,
      ...authConfig,
    };
    const expected = {
      id: modelId,
      name: "DeepSeek V4.1 Flash 1017 Cyber",
      provider: "inference",
      contextLength: 1_040_000,
    };
    expect(AVAILABLE_MODELS.filter((m) => m.provider === "inference")).toEqual([
      expected,
    ]);
    expect(hasAnyProviderConfigured(config)).toBe(true);
    expect(getConfiguredProviders(config)).toContainEqual(
      expect.objectContaining({ id: "inference", configured: true }),
    );
    expect(getAvailableModels(config)).toEqual([expected]);
    expect(getDefaultModelForConfig(config)).toEqual(expected);
    expect(getSavedModelForConfig(config)).toEqual(expected);
    expect(getContextWindow(modelId)).toBe(1_040_000);
    expect(getMaxOutputTokens(modelId)).toBe(393_216);
    expect(resolveExplicitCliModel({ model: modelId })).toBe(modelId);
    expect(getReasoningCapabilities(modelId).control).toBe("none");
  });

  it.each([
    undefined,
    "",
    "   ",
  ])("requires its own nonempty credential (%s)", (inferenceAPIKey) => {
    vi.stubEnv("INFERENCE_API_KEY", "");
    vi.stubEnv("OPENAI_API_KEY", "must-not-use");
    const config = { responsibleUseAccepted: true, inferenceAPIKey };
    expect(hasAnyProviderConfigured(config)).toBe(false);
    expect(getAvailableModels(config)).toEqual([]);
    expect(() => getProviderModel(modelId, { inferenceAPIKey })).toThrow(
      "INFERENCE_API_KEY",
    );
  });

  it("routes to Inference.net with the bare model ID and saved key before the environment key", async () => {
    vi.stubEnv("INFERENCE_API_KEY", "env-key");
    vi.stubEnv("OPENAI_API_KEY", "must-not-forward");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion("ok"),
    );
    vi.stubGlobal("fetch", fetchMock);
    for (const auth of [authConfig, undefined]) {
      const model = getProviderModel(modelId, auth);
      expect(model.provider).toBe("inference.chat");
      await model.doGenerate({ prompt: [], maxOutputTokens: 256 });
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [index, [url, init]] of fetchMock.mock.calls.entries()) {
      expect(url).toBe("https://api.inference.net/v1/chat/completions");
      expect(new Headers(init?.headers).get("authorization")).toBe(
        index === 0 ? "Bearer inference-test-key" : "Bearer env-key",
      );
      expect(JSON.parse(String(init?.body))).toMatchObject({
        model: upstreamId,
        max_tokens: 256,
      });
    }
  });

  it("preserves streamed reasoning and tool calls across a tool round trip and resume", async () => {
    const responses = [
      sse(
        [
          { reasoning_content: "Inspect the probe." },
          {
            tool_calls: [
              {
                index: 0,
                id: "call_1",
                type: "function",
                function: { name: "echo_probe", arguments: '{"value":' },
              },
            ],
          },
          { tool_calls: [{ index: 0, function: { arguments: '"probe"}' } }] },
        ],
        "tool_calls",
      ),
      sse([{ content: "DONE" }]),
      sse([{ content: "resumed" }]),
    ];
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) => {
      const response = responses.shift();
      if (!response) throw new Error("Unexpected request");
      return response;
    });
    vi.stubGlobal("fetch", fetchMock);
    const execute = vi.fn(async ({ value }: { value: string }) => ({
      echoed: value,
    }));
    const tools = {
      echo_probe: {
        description: "Echo a synthetic value",
        inputSchema: z.object({ value: z.string() }),
        execute,
      },
    };
    const run = streamResponse({
      model: modelId,
      authConfig,
      prompt: "Echo probe",
      tools,
      openAIReasoningEffort: "high",
      stopWhen: stepCountIs(2),
      silent: true,
    });
    await consumeStream(run, {});
    expect(await run.text).toBe("DONE");
    expect(execute).toHaveBeenCalledOnce();
    const history = JSON.parse(
      JSON.stringify((await run.response).messages),
    ) as ModelMessage[];
    const resumed = streamResponse({
      model: modelId,
      authConfig,
      prompt: "",
      messages: [
        { role: "user", content: "Echo probe" },
        ...history,
        { role: "user", content: "Continue" },
      ],
      tools,
      silent: true,
    });
    await consumeStream(resumed, {});
    expect(await resumed.text).toBe("resumed");
    expect(fetchMock).toHaveBeenCalledTimes(3);
    for (const [index, [url, init]] of fetchMock.mock.calls.entries()) {
      expect(url).toBe("https://api.inference.net/v1/chat/completions");
      const body = JSON.parse(String(init?.body));
      expect(body).toMatchObject({
        model: upstreamId,
        stream: true,
        max_tokens: 393_216,
      });
      expect(body).not.toHaveProperty("reasoning_effort");
      expect(body).not.toHaveProperty("prompt_cache_key");
      if (index === 0) continue;
      expect(body.messages).toContainEqual(
        expect.objectContaining({
          role: "assistant",
          reasoning_content: "Inspect the probe.",
          tool_calls: [expect.objectContaining({ id: "call_1" })],
        }),
      );
      expect(body.messages).toContainEqual(
        expect.objectContaining({
          role: "tool",
          tool_call_id: "call_1",
          content: '{"echoed":"probe"}',
        }),
      );
    }
  });

  it("uses schema-constrained output for structured generation", async () => {
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion('{"ok":true}'),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      generateObjectResponse({
        model: modelId,
        authConfig,
        prompt: "Return ok",
        schema: z.object({ ok: z.boolean() }),
      }),
    ).resolves.toEqual({ ok: true });
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toMatchObject({
      model: upstreamId,
      max_tokens: 393_216,
      response_format: { type: "json_schema" },
    });
  });

  it("surfaces the provider's model access error without retrying", async () => {
    const message =
      "Model requires approved access. Request access at https://inference.net/model-access/deepseek-v4.1-flash-1017-cyber";
    const fetchMock = vi.fn(async () =>
      Response.json(
        {
          error: {
            message,
            type: "model_access_required",
          },
        },
        { status: 403 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      getProviderModel(modelId, authConfig).doGenerate({ prompt: [] }),
    ).rejects.toMatchObject({
      message,
      statusCode: 403,
      isRetryable: false,
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
