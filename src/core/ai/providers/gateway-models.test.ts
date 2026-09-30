import type { LanguageModelV3CallOptions } from "@ai-sdk/provider";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getVisiblePickerModels } from "../../../tui/components/model-picker/model-visibility";
import { resolveExplicitCliModel } from "../../cli/model";
import { getAvailableModels } from "../../providers/utils";
import {
  buildReasoningProviderOptions,
  getOpenAIReasoningEfforts,
} from "../ai";
import { getMaxOutputTokens } from "../models";
import { getProviderModel } from "../utils";

const models = [
  {
    slug: "gpt-5.4-mini",
    context: 400_000,
    openrouter: "openai/gpt-5.4-mini",
    concentrate: true,
  },
];
const routes = models.flatMap(({ slug, context, openrouter, concentrate }) => [
  {
    id: openrouter,
    upstream: openrouter,
    context,
    provider: "openrouter" as const,
  },
  ...(concentrate
    ? [
        {
          id: `concentrate:${slug}`,
          upstream: slug,
          context,
          provider: "concentrate" as const,
        },
      ]
    : []),
]);

afterEach(() => vi.unstubAllGlobals());

function completedResponse(upstream: string, openrouter: boolean) {
  return Response.json(
    openrouter
      ? {
          id: "chat_test",
          created: 1,
          model: upstream,
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: '{"ok":true}' },
              finish_reason: "stop",
            },
          ],
          usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 },
        }
      : {
          id: "resp_test",
          created_at: 1,
          model: upstream,
          output: [
            {
              type: "message",
              role: "assistant",
              id: "msg_test",
              content: [
                { type: "output_text", text: '{"ok":true}', annotations: [] },
              ],
            },
          ],
          usage: { input_tokens: 12, output_tokens: 8 },
        },
  );
}

function toolStream(upstream: string, openrouter: boolean) {
  const item = {
    type: "function_call",
    id: "fc_test",
    call_id: "call_test",
    name: "check",
    arguments: "{}",
    status: "completed",
  };
  const events = openrouter
    ? [
        {
          id: "chat_test",
          created: 1,
          model: upstream,
          choices: [
            {
              index: 0,
              delta: {
                role: "assistant",
                tool_calls: [
                  {
                    index: 0,
                    id: "call_test",
                    type: "function",
                    function: { name: "check", arguments: "{}" },
                  },
                ],
              },
              finish_reason: null,
            },
          ],
        },
        {
          id: "chat_test",
          created: 1,
          model: upstream,
          choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
          usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 },
        },
      ]
    : [
        {
          type: "response.created",
          response: { id: "resp_test", created_at: 1, model: upstream },
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
        { type: "response.output_item.done", output_index: 0, item },
        {
          type: "response.completed",
          response: {
            id: "resp_test",
            created_at: 1,
            model: upstream,
            output: [item],
            usage: { input_tokens: 12, output_tokens: 8 },
          },
        },
      ];
  return new Response(
    events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("") +
      (openrouter ? "data: [DONE]\n\n" : ""),
    { headers: { "content-type": "text/event-stream" } },
  );
}

describe.each(routes)("Gateway $id", ({ id, upstream, provider, context }) => {
  const openrouter = provider === "openrouter";
  const credentials = openrouter
    ? { openRouterAPIKey: "test-router-key" }
    : { concentrateAPIKey: "sk-cn-test" };
  const options = (): LanguageModelV3CallOptions => ({
    prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
    maxOutputTokens: getMaxOutputTokens(id),
    tools: [
      {
        type: "function",
        name: "check",
        inputSchema: { type: "object", properties: {} },
      },
    ],
    toolChoice: { type: "auto" },
    providerOptions: buildReasoningProviderOptions(id, {
      openAIReasoningEffort: "high",
    }),
  });

  it("exposes only the configured route in the picker and CLI with its limits", () => {
    const available = getVisiblePickerModels(
      getAvailableModels({ responsibleUseAccepted: true, ...credentials }),
    );
    expect(available.find((m) => m.id === id)).toMatchObject({
      provider,
      contextLength: context,
    });
    expect(
      getAvailableModels({ responsibleUseAccepted: true }).some(
        (m) => m.id === id,
      ),
    ).toBe(false);
    expect(resolveExplicitCliModel({ model: id })).toBe(id);
    expect(getMaxOutputTokens(id)).toBe(128_000);
    expect(getOpenAIReasoningEfforts(id)).toContain("high");
  });

  it("sends the upstream ID, credentials, output budget, tools, schema and reasoning", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        completedResponse(upstream, openrouter),
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = await getProviderModel(id, credentials).doGenerate({
      ...options(),
      responseFormat: {
        type: "json",
        schema: {
          type: "object",
          properties: { ok: { type: "boolean" } },
          required: ["ok"],
          additionalProperties: false,
        },
      },
    });
    expect(result.content).toContainEqual(
      expect.objectContaining({ type: "text", text: '{"ok":true}' }),
    );
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected gateway request");
    const [url, init] = call;
    expect(String(url)).toBe(
      openrouter
        ? "https://openrouter.ai/api/v1/chat/completions"
        : "https://api.concentrate.ai/v1/responses",
    );
    expect(new Headers(init?.headers).get("authorization")).toBe(
      openrouter ? "Bearer test-router-key" : "Bearer sk-cn-test",
    );
    const body = JSON.parse(String(init?.body));
    expect(body.model).toBe(upstream);
    expect(body.reasoning).toMatchObject({ effort: "high" });
    if (openrouter) {
      expect(body).toMatchObject({
        max_tokens: 128_000,
        tools: [{ type: "function", function: { name: "check" } }],
        response_format: { type: "json_schema" },
      });
    } else {
      expect(body).toMatchObject({
        store: false,
        max_output_tokens: 128_000,
        tools: [{ type: "function", name: "check" }],
        text: { format: { type: "json_schema" } },
      });
    }
  });

  it("streams tool calls and sends the next tool result through the same route", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) =>
        JSON.parse(String(init?.body)).stream
          ? toolStream(upstream, openrouter)
          : completedResponse(upstream, openrouter),
    );
    vi.stubGlobal("fetch", fetchMock);
    const model = getProviderModel(id, credentials);
    const { stream } = await model.doStream(options());
    const chunks = [];
    const reader = stream.getReader();
    for (let next = await reader.read(); !next.done; next = await reader.read())
      chunks.push(next.value);
    expect(chunks).toContainEqual(
      expect.objectContaining({
        type: "tool-call",
        toolCallId: "call_test",
        toolName: "check",
        input: "{}",
      }),
    );
    expect(chunks).toContainEqual(expect.objectContaining({ type: "finish" }));
    await model.doGenerate({
      ...options(),
      prompt: [
        ...options().prompt,
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
    const call = fetchMock.mock.calls[1];
    if (!call) throw new Error("Expected tool-result request");
    const body = JSON.parse(String(call[1]?.body));
    expect(body.model).toBe(upstream);
    if (openrouter)
      expect(body.messages).toContainEqual(
        expect.objectContaining({
          role: "tool",
          tool_call_id: "call_test",
          content: '{"ok":true}',
        }),
      );
    else
      expect(body.input).toContainEqual(
        expect.objectContaining({
          type: "function_call_output",
          call_id: "call_test",
          output: '{"ok":true}',
        }),
      );
  });
});
