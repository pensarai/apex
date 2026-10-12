import { type ModelMessage, stepCountIs } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { CustomProviders } from "../../config/customProviders";
import {
  generateObjectResponse,
  getContextWindow,
  streamResponse,
} from "../ai";
import { getMaxOutputTokens } from "../models";
import { buildAuthConfig, consumeStream, getProviderModel } from "../utils";

const modelId = "custom:research:glm-5.3";
const customProviders: CustomProviders = {
  research: {
    baseUrl: "https://inference.example/api/paas/v4",
    apiKeyEnv: "APEX_TEST_CUSTOM_KEY",
    headers: { "Accept-Language": "en-US,en" },
    requestBody: {
      temperature: 1,
      reasoning_effort: "max",
      thinking: { type: "enabled", clear_thinking: false },
    },
    models: [
      { id: "glm-5.3", contextLength: 200_000, maxOutputTokens: 32_000 },
    ],
  },
};

function completion(text: string): Response {
  return Response.json({
    id: "test",
    object: "chat.completion",
    created: 1,
    model: "glm-5.3",
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
  const chunks: unknown[] = deltas.map((delta) => ({
    id: "test",
    model: "glm-5.3",
    choices: [{ index: 0, delta, finish_reason: null }],
  }));
  chunks.push({
    id: "test",
    model: "glm-5.3",
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

describe("custom inference", () => {
  it("uses the configured endpoint, bearer key, GLM settings, and output budget", async () => {
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "test-secret");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion("ok"),
    );
    vi.stubGlobal("fetch", fetchMock);
    const authConfig = buildAuthConfig({ customProviders });
    await getProviderModel(modelId, authConfig).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Say ok" }] }],
      maxOutputTokens: 100_000,
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://inference.example/api/paas/v4/chat/completions");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer test-secret",
    );
    expect(new Headers(init?.headers).get("accept-language")).toBe("en-US,en");
    expect(JSON.parse(String(init?.body))).toMatchObject({
      model: "glm-5.3",
      max_tokens: 32_000,
      ...customProviders.research.requestBody,
    });
    expect(getContextWindow(modelId, customProviders)).toBe(200_000);
    expect(getMaxOutputTokens(modelId, customProviders)).toBe(32_000);
    expect(JSON.stringify(authConfig)).not.toContain("test-secret");
  });

  it("supports a worker environment without a local Apex config", async () => {
    vi.stubEnv("APEX_CUSTOM_PROVIDERS", JSON.stringify(customProviders));
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "test-secret");
    expect(getProviderModel(modelId).modelId).toBe("glm-5.3");
    expect(getContextWindow(modelId)).toBe(200_000);
  });

  it("supports unauthenticated local inference without borrowing another key", async () => {
    vi.stubEnv("OPENAI_API_KEY", "must-not-forward");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion("ok"),
    );
    vi.stubGlobal("fetch", fetchMock);
    const local = {
      research: { ...customProviders.research, apiKeyEnv: undefined },
    };
    await getProviderModel(modelId, { customProviders: local }).doGenerate({
      prompt: [],
    });
    expect(
      new Headers(fetchMock.mock.calls[0][1]?.headers).has("authorization"),
    ).toBe(false);
  });

  it("preserves reasoning through a streamed tool round trip and serialized resume", async () => {
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "test-secret");
    const responses = [
      sse(
        [
          { reasoning_content: "Inspect the " },
          { reasoning_content: "test value." },
          {
            tool_calls: [
              {
                index: 0,
                id: "call_1",
                type: "function",
                function: { name: "lookup", arguments: '{"value":"test"}' },
              },
            ],
          },
        ],
        "tool_calls",
      ),
      sse([{ reasoning_content: "The tool succeeded." }, { content: "done" }]),
      sse([{ content: "resumed" }]),
    ];
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) => {
      const response = responses.shift();
      if (!response) throw new Error("Unexpected inference request");
      return response;
    });
    vi.stubGlobal("fetch", fetchMock);
    const lookup = vi.fn(async () => "found");
    const tools = {
      lookup: {
        description: "Look up a test value",
        inputSchema: z.object({ value: z.string() }),
        execute: lookup,
      },
    };
    const run = await streamResponse({
      model: modelId,
      authConfig: { customProviders },
      prompt: "Look up test",
      tools,
      stopWhen: stepCountIs(2),
      silent: true,
    });
    await consumeStream(run, {});
    expect(await run.text).toBe("done");
    expect(lookup).toHaveBeenCalledOnce();
    const secondBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body));
    expect(secondBody.messages).toContainEqual(
      expect.objectContaining({
        role: "assistant",
        reasoning_content: "Inspect the test value.",
        tool_calls: [expect.objectContaining({ id: "call_1" })],
      }),
    );
    expect(secondBody.messages).toContainEqual(
      expect.objectContaining({
        role: "tool",
        tool_call_id: "call_1",
        content: "found",
      }),
    );
    const history = JSON.parse(
      JSON.stringify((await run.response).messages),
    ) as ModelMessage[];
    const resumed = await streamResponse({
      model: modelId,
      authConfig: { customProviders },
      prompt: "",
      messages: [
        { role: "user", content: "Look up test" },
        ...history,
        { role: "user", content: "Continue" },
      ],
      tools,
      silent: true,
    });
    await consumeStream(resumed, {});
    expect(await resumed.text).toBe("resumed");
    const lastBody = JSON.parse(String(fetchMock.mock.calls[2][1]?.body));
    expect(
      lastBody.messages
        .filter((m: { reasoning_content?: string }) => m.reasoning_content)
        .map((m: { reasoning_content: string }) => m.reasoning_content),
    ).toEqual(["Inspect the test value.", "The tool succeeded."]);
    for (const [, init] of fetchMock.mock.calls)
      expect(JSON.parse(String(init?.body))).toMatchObject({
        stream: true,
        model: "glm-5.3",
        ...customProviders.research.requestBody,
      });
  });

  it("applies the same provider settings to structured generations", async () => {
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "test-secret");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      completion('{"ok":true}'),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect(
      await generateObjectResponse({
        model: modelId,
        authConfig: { customProviders },
        prompt: "Return ok",
        schema: z.object({ ok: z.boolean() }),
      }),
    ).toEqual({ ok: true });
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toMatchObject({
      response_format: { type: "json_object" },
      ...customProviders.research.requestBody,
    });
  });
});
