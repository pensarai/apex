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

vi.mock("undici", async (importOriginal) => {
  const original = await importOriginal<typeof import("undici")>();
  return {
    ...original,
    fetch: (input: RequestInfo | URL, init?: RequestInit) =>
      globalThis.fetch(input, init),
  };
});

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
const responsesModelId = "custom:responses:org/reasoning-model";
const responsesProviders: CustomProviders = {
  responses: {
    baseUrl: "https://inference.example/v1",
    apiType: "responses",
    apiKeyEnv: "APEX_TEST_RESPONSES_KEY",
    headers: { "X-Test-Provider": "research" },
    models: [
      {
        id: "org/reasoning-model",
        contextLength: 200_000,
        maxOutputTokens: 32_000,
        reasoningEffort: "xhigh",
      },
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

function responsesCompletion(text: string): Response {
  return Response.json({
    id: "resp_test",
    created_at: 1,
    model: "org/reasoning-model",
    output: [
      {
        type: "message",
        role: "assistant",
        id: "msg_test",
        content: [{ type: "output_text", text, annotations: [] }],
      },
    ],
    usage: { input_tokens: 12, output_tokens: 8 },
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
  it("sends configured effort, credentials, and output budget through Responses", async () => {
    vi.stubEnv("APEX_TEST_RESPONSES_KEY", "test-secret");
    vi.stubEnv("OPENAI_API_KEY", "wrong-key");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      responsesCompletion("ok"),
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = await getProviderModel(responsesModelId, {
      customProviders: responsesProviders,
    }).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Say ok" }] }],
      maxOutputTokens: 100_000,
    });
    expect(result.content).toContainEqual(
      expect.objectContaining({ type: "text", text: "ok" }),
    );
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://inference.example/v1/responses");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer test-secret",
    );
    expect(new Headers(init?.headers).get("x-test-provider")).toBe("research");
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      model: "org/reasoning-model",
      max_output_tokens: 32_000,
      reasoning: { effort: "xhigh" },
    });
    expect(body.max_tokens).toBeUndefined();
    expect(getContextWindow(responsesModelId, responsesProviders)).toBe(
      200_000,
    );
    expect(getMaxOutputTokens(responsesModelId, responsesProviders)).toBe(
      32_000,
    );
  });

  it("omits reasoning when the Responses model has no effort setting", async () => {
    vi.stubEnv("APEX_TEST_RESPONSES_KEY", "test-secret");
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      responsesCompletion("ok"),
    );
    vi.stubGlobal("fetch", fetchMock);
    const providers: CustomProviders = {
      responses: {
        ...responsesProviders.responses,
        models: [
          {
            id: "org/reasoning-model",
            contextLength: 200_000,
            maxOutputTokens: 32_000,
          },
        ],
      },
    };
    await getProviderModel(responsesModelId, {
      customProviders: providers,
    }).doGenerate({ prompt: [] });
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    expect(body.reasoning).toBeUndefined();
    expect(body.max_output_tokens).toBe(32_000);
  });

  it("rejects an unvalidated Responses provider without its own key", () => {
    vi.stubEnv("OPENAI_API_KEY", "must-not-borrow");
    const providers: CustomProviders = {
      responses: { ...responsesProviders.responses, apiKeyEnv: undefined },
    };
    expect(() =>
      getProviderModel(responsesModelId, { customProviders: providers }),
    ).toThrow("require apiKeyEnv");
  });

  it("streams a Responses tool call and sends its result on the next turn", async () => {
    vi.stubEnv("APEX_TEST_RESPONSES_KEY", "test-secret");
    const item = {
      status: "completed",
      type: "function_call",
      id: "fc_test",
      call_id: "call_test",
      name: "check",
      arguments: "{}",
    };
    const events = [
      {
        type: "response.created",
        response: {
          id: "resp_stream",
          created_at: 1,
          model: "org/reasoning-model",
        },
      },
      {
        type: "response.output_item.added",
        output_index: 0,
        item: { ...item, arguments: "" },
      },
      {
        type: "response.function_call_arguments.delta",
        output_index: 0,
        item_id: "fc_test",
        delta: "{}",
      },
      {
        type: "response.function_call_arguments.done",
        output_index: 0,
        item_id: "fc_test",
        arguments: "{}",
      },
      { type: "response.output_item.done", output_index: 0, item },
      {
        type: "response.completed",
        response: {
          id: "resp_stream",
          created_at: 1,
          model: "org/reasoning-model",
          output: [item],
          usage: { input_tokens: 12, output_tokens: 8 },
        },
      },
    ];
    const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
      if (!JSON.parse(String(init?.body)).stream)
        return responsesCompletion("done");
      return new Response(
        events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
        { headers: { "content-type": "text/event-stream" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const model = getProviderModel(responsesModelId, {
      customProviders: responsesProviders,
    });
    const { stream } = await model.doStream({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      tools: [
        {
          type: "function",
          name: "check",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });
    const chunks = [];
    const reader = stream.getReader();
    for (let next = await reader.read(); !next.done; next = await reader.read())
      chunks.push(next.value);
    expect(chunks).toContainEqual(
      expect.objectContaining({
        type: "tool-call",
        toolCallId: "call_test",
        toolName: "check",
      }),
    );
    await model.doGenerate({
      prompt: [
        { role: "user", content: [{ type: "text", text: "Check" }] },
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              toolCallId: "call_test",
              toolName: "check",
              input: {},
            },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "call_test",
              toolName: "check",
              output: { type: "json", value: { ok: true } },
            },
          ],
        },
      ],
    });
    const firstBody = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    const secondBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body));
    expect(firstBody).toMatchObject({
      stream: true,
      reasoning: { effort: "xhigh" },
    });
    expect(secondBody).toMatchObject({ reasoning: { effort: "xhigh" } });
    expect(secondBody.input).toContainEqual(
      expect.objectContaining({
        type: "function_call_output",
        call_id: "call_test",
        output: '{"ok":true}',
      }),
    );
  });

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
