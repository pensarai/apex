import type { LanguageModelV3CallOptions } from "@ai-sdk/provider";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getVisiblePickerModels } from "../../../tui/components/model-picker/model-visibility";
import { resolveExplicitCliModel } from "../../cli/model";
import { getAvailableModels } from "../../providers/utils";
import {
  buildReasoningProviderOptions,
  getOpenAIReasoningEfforts,
  normalizeOpenAIReasoningEffort,
} from "../ai";
import { getMaxOutputTokens } from "../models";
import { getProviderModel } from "../utils";

const models = [
  {
    ids: ["gpt-6-astra"],
    context: 1050000,
    efforts: ["low", "medium", "high", "xhigh", "max"],
  },
  {
    ids: ["gpt-5.5-pro", "gpt-5.5-pro-2026-04-23"],
    context: 1_050_000,
    efforts: ["medium", "high", "xhigh"],
  },
  {
    ids: ["gpt-5.4-nano", "gpt-5.4-nano-2026-03-17"],
    context: 400_000,
    efforts: ["none", "low", "medium", "high", "xhigh"],
  },
  {
    ids: ["gpt-5.4-mini", "gpt-5.4-mini-2026-03-17"],
    context: 400_000,
    efforts: ["none", "low", "medium", "high", "xhigh"],
  },
];

function completion(model: string) {
  return Response.json({
    id: "resp_test",
    created_at: 1,
    model,
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
  });
}

afterEach(() => vi.unstubAllGlobals());

it.each([
  "gpt-5.5-pro",
  "gpt-5.5-pro-2026-04-23",
])("adapts %s non-streaming tool calls into the agent stream", async (id) => {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json({
        id: "resp_tool",
        created_at: 1,
        model: id,
        output: [
          {
            type: "function_call",
            id: "fc_test",
            call_id: "call_test",
            name: "check",
            arguments: "{}",
          },
        ],
        usage: { input_tokens: 12, output_tokens: 8 },
      }),
  );
  vi.stubGlobal("fetch", fetchMock);
  const model = getProviderModel(id, { openAiAPIKey: "test-key" });
  const abortSignal = new AbortController().signal;
  const { stream } = await model.doStream({
    prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
    tools: [
      {
        type: "function",
        name: "check",
        inputSchema: { type: "object", properties: {} },
      },
    ],
    abortSignal,
  });
  const chunks = [];
  const reader = stream.getReader();
  for (let next = await reader.read(); !next.done; next = await reader.read()) {
    chunks.push(next.value);
  }
  expect(chunks).toContainEqual(
    expect.objectContaining({
      type: "tool-call",
      toolCallId: "call_test",
      toolName: "check",
      input: "{}",
    }),
  );
  expect(chunks).toContainEqual(
    expect.objectContaining({
      type: "finish",
      usage: expect.objectContaining({
        inputTokens: expect.objectContaining({ total: 12 }),
      }),
    }),
  );
  const call = fetchMock.mock.calls[0];
  if (!call) throw new Error("Expected a Pro request");
  expect(JSON.parse(String(call[1]?.body)).stream).toBeUndefined();
  expect(call[1]?.signal).toBe(abortSignal);
});

describe.each(models)("OpenAI $ids", ({ ids, context, efforts }) => {
  it.each(
    ids,
  )("exposes %s in the picker and CLI with its limits and effort levels", (id) => {
    const available = getVisiblePickerModels(
      getAvailableModels({
        responsibleUseAccepted: true,
        openAiAPIKey: "test-key",
      }),
    );
    expect(available.find((m) => m.id === id)).toMatchObject({
      provider: "openai",
      contextLength: context,
    });
    expect(resolveExplicitCliModel({ model: id })).toBe(id);
    expect(getMaxOutputTokens(id)).toBe(128_000);
    expect(getOpenAIReasoningEfforts(id)).toEqual(efforts);
    expect(efforts).toContain(normalizeOpenAIReasoningEffort(id, "ultra"));
  });

  it.each(
    ids,
  )("sends %s tools, JSON schema and effort to Responses", async (id) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => completion(id),
    );
    vi.stubGlobal("fetch", fetchMock);
    const model = getProviderModel(id, { openAiAPIKey: "test-key" });
    const options = {
      prompt: [
        { role: "user", content: [{ type: "text", text: "Check the result" }] },
      ],
      maxOutputTokens: getMaxOutputTokens(id),
      tools: [
        {
          type: "function",
          name: "check",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      toolChoice: { type: "auto" },
      responseFormat: {
        type: "json",
        schema: {
          type: "object",
          properties: { ok: { type: "boolean" } },
          required: ["ok"],
          additionalProperties: false,
        },
      },
      providerOptions: buildReasoningProviderOptions(id, {
        openAIReasoningEffort: "high",
      }),
    } satisfies LanguageModelV3CallOptions;
    const result = await model.doGenerate(options);
    expect(result.content).toContainEqual(
      expect.objectContaining({ type: "text", text: '{"ok":true}' }),
    );
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected an OpenAI request");
    const [url, init] = call;
    expect(String(url)).toBe("https://api.openai.com/v1/responses");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer test-key",
    );
    expect(JSON.parse(String(init?.body))).toMatchObject({
      model: id,
      max_output_tokens: 128_000,
      reasoning: { effort: "high" },
      tools: [{ type: "function", name: "check" }],
      text: { format: { type: "json_schema" } },
    });
  });
});

it.each(
  models.flatMap((model) => model.ids).filter((id) => !id.includes("-pro")),
)("streams %s tool calls and accepts the next tool result", async (id) => {
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
      response: { id: "resp_stream", created_at: 1, model: id },
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
        model: id,
        output: [item],
        usage: { input_tokens: 12, output_tokens: 8 },
      },
    },
  ];
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (!JSON.parse(String(init?.body)).stream) return completion(id);
      return new Response(
        events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
        { headers: { "content-type": "text/event-stream" } },
      );
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  const model = getProviderModel(id, { openAiAPIKey: "test-key" });
  const { stream } = await model.doStream({
    prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
    tools: [
      {
        type: "function",
        name: "check",
        inputSchema: { type: "object", properties: {} },
      },
    ],
    providerOptions: buildReasoningProviderOptions(id, {
      openAIReasoningEffort: "high",
    }),
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
      input: "{}",
    }),
  );
  const first = fetchMock.mock.calls[0];
  if (!first) throw new Error("Expected a streaming request");
  expect(JSON.parse(String(first[1]?.body))).toMatchObject({
    stream: true,
    reasoning: { effort: "high" },
  });
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
  const second = fetchMock.mock.calls[1];
  if (!second) throw new Error("Expected a tool-result request");
  expect(JSON.parse(String(second[1]?.body)).input).toContainEqual(
    expect.objectContaining({
      type: "function_call_output",
      call_id: "call_test",
      output: '{"ok":true}',
    }),
  );
});
