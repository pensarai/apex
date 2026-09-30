import { type ModelMessage, stepCountIs } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { resolveExplicitCliModel } from "../../cli/model";
import {
  getAvailableModels,
  getDefaultModelForConfig,
  hasAnyProviderConfigured,
} from "../../providers/utils";
import {
  generateObjectResponse,
  getContextWindow,
  streamResponse,
} from "../ai";
import { getMaxOutputTokens, getModelInfo } from "../models";
import { buildAuthConfig, consumeStream, getProviderModel } from "../utils";

const upstreamId = "Qwen/Qwen3.6-27B";
const modelId = `hoonify:${upstreamId}`;
const hoonifyModels = [
  { id: upstreamId, contextLength: 262_144, maxOutputTokens: 4096 },
];
const authConfig = buildAuthConfig({
  hoonifyAPIKey: "hoonify-test-key",
  hoonifyModels,
});

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

describe("built-in Hoonify inference", () => {
  it("selects discovered models in the picker and CLI with matching budgets", () => {
    const cfg = { responsibleUseAccepted: true, ...authConfig };
    expect(hasAnyProviderConfigured(cfg)).toBe(true);
    expect(getAvailableModels(cfg)).toEqual([
      {
        id: modelId,
        name: upstreamId,
        provider: "hoonify",
        contextLength: 262_144,
      },
    ]);
    expect(getDefaultModelForConfig(cfg)?.id).toBe(modelId);
    expect(
      getDefaultModelForConfig({ ...cfg, anthropicAPIKey: "other-key" })
        ?.provider,
    ).toBe("anthropic");
    expect(
      getDefaultModelForConfig({ ...cfg, inceptionAPIKey: "other-key" })
        ?.provider,
    ).toBe("inception");
    expect(
      getDefaultModelForConfig({ ...cfg, localModelName: "local-model" })
        ?.provider,
    ).toBe("local");
    expect(getModelInfo(modelId).provider).toBe("hoonify");
    expect(getContextWindow(modelId, undefined, hoonifyModels)).toBe(262_144);
    expect(getMaxOutputTokens(modelId, undefined, hoonifyModels)).toBe(4096);
    expect(
      resolveExplicitCliModel({
        model: upstreamId,
        provider: "hoonify",
        hoonifyModels,
      }),
    ).toBe(modelId);
    expect(resolveExplicitCliModel({ model: modelId, hoonifyModels })).toBe(
      modelId,
    );
    expect(() =>
      resolveExplicitCliModel({ model: "hoonify:unknown", hoonifyModels }),
    ).toThrow("unavailable");
    expect(() =>
      resolveExplicitCliModel({
        model: modelId,
        hoonifyCatalogError: "catalog failure",
      }),
    ).toThrow("catalog failure");
  });

  it("routes only to Hoonify with the exact upstream ID and capped output", async () => {
    vi.stubEnv("OPENAI_API_KEY", "must-not-forward");
    vi.stubEnv("HOONIFY_API_KEY", "env-key");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion("ok"),
    );
    vi.stubGlobal("fetch", fetchMock);
    await getProviderModel(modelId, authConfig).doGenerate({
      prompt: [],
      maxOutputTokens: 100_000,
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.hoonify.ai/v1/chat/completions");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer hoonify-test-key",
    );
    expect(JSON.parse(String(init?.body))).toMatchObject({
      model: upstreamId,
      max_tokens: 4096,
    });
    await getProviderModel(modelId, { hoonifyModels }).doGenerate({
      prompt: [],
      maxOutputTokens: 256,
    });
    expect(
      new Headers(fetchMock.mock.calls[1][1]?.headers).get("authorization"),
    ).toBe("Bearer env-key");
    expect(
      JSON.parse(String(fetchMock.mock.calls[1][1]?.body)).max_tokens,
    ).toBe(256);
  });

  it("fails before inference on missing credentials or unknown models", () => {
    vi.stubEnv("HOONIFY_API_KEY", "");
    vi.stubEnv("OPENAI_API_KEY", "must-not-forward");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(() => getProviderModel(modelId, { hoonifyModels })).toThrow(
      "HOONIFY_API_KEY",
    );
    expect(() => getProviderModel("hoonify:unknown", authConfig)).toThrow(
      "unavailable",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("streams fragmented tool calls and preserves tool/reasoning history on resume", async () => {
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
      stopWhen: stepCountIs(2),
      silent: true,
    });
    await consumeStream(run, {});
    expect(await run.text).toBe("DONE");
    expect(execute).toHaveBeenCalledOnce();
    const secondBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body));
    expect(secondBody.messages).toContainEqual(
      expect.objectContaining({
        role: "assistant",
        reasoning_content: "Inspect the probe.",
        tool_calls: [expect.objectContaining({ id: "call_1" })],
      }),
    );
    expect(secondBody.messages).toContainEqual(
      expect.objectContaining({
        role: "tool",
        tool_call_id: "call_1",
        content: '{"echoed":"probe"}',
      }),
    );
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
    const resumedBody = JSON.parse(String(fetchMock.mock.calls[2][1]?.body));
    expect(resumedBody.messages).toContainEqual(
      expect.objectContaining({
        role: "assistant",
        reasoning_content: "Inspect the probe.",
      }),
    );
    for (const [url, init] of fetchMock.mock.calls) {
      expect(url).toBe("https://api.hoonify.ai/v1/chat/completions");
      expect(JSON.parse(String(init?.body))).toMatchObject({
        model: upstreamId,
        stream: true,
        max_tokens: 4096,
      });
    }
  });

  it("requests schema-constrained output through Hoonify", async () => {
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion('{"ok":true}'),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect(
      await generateObjectResponse({
        model: modelId,
        authConfig,
        prompt: "Return ok",
        schema: z.object({ ok: z.boolean() }),
      }),
    ).toEqual({ ok: true });
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toMatchObject({
      model: upstreamId,
      max_tokens: 4096,
      response_format: {
        type: "json_schema",
        json_schema: {
          schema: { properties: { ok: { type: "boolean" } }, required: ["ok"] },
        },
      },
    });
  });
});
