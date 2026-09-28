import {
  APICallError,
  type LanguageModelV3CallOptions,
} from "@ai-sdk/provider";
import { describe, expect, it, vi } from "vitest";
import {
  CONCENTRATE_BASE_URL,
  type ConcentrateFetch,
  createConcentrateFetch,
  createConcentrateModel,
  extractConcentrateResponseMetadata,
} from "./concentrate";

function completedResponse(): Response {
  return new Response(
    JSON.stringify({
      id: "resp_1",
      created_at: 1_786_665_600,
      model: "fireworks/glm-5.3",
      output: [
        {
          type: "message",
          role: "assistant",
          id: "msg_1",
          content: [{ type: "output_text", text: "ok", annotations: [] }],
        },
      ],
      usage: {
        input_tokens: 12,
        input_tokens_details: { cached_tokens: 4 },
        output_tokens: 8,
        output_tokens_details: { reasoning_tokens: 3 },
      },
      cost: {
        total: 0.000019,
        byok: false,
        breakdown: {
          "fireworks/glm-5.3": {
            input_tokens: 12,
            output_tokens: 8,
            total_tokens: 20,
          },
        },
      },
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-request-id": "req_123",
      },
    },
  );
}

function streamedResponse(): Response {
  const events = [
    {
      type: "response.created",
      response: {
        id: "resp_stream",
        created_at: 1_786_665_600,
        model: "fireworks/glm-5.3",
      },
    },
    {
      type: "response.output_text.delta",
      item_id: "msg_1",
      delta: "ok",
    },
    {
      type: "response.completed",
      response: {
        model: "fireworks/glm-5.3",
        usage: {
          input_tokens: 12,
          input_tokens_details: { cached_tokens: 4 },
          output_tokens: 8,
          output_tokens_details: { reasoning_tokens: 3 },
        },
        cost: {
          total: 0.000019,
          byok: false,
          breakdown: {
            "fireworks/glm-5.3": {
              input_tokens: 12,
              output_tokens: 8,
              total_tokens: 20,
            },
          },
        },
      },
    },
  ];
  return new Response(
    `${events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("")}data: [DONE]\n\n`,
    {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    },
  );
}

describe("createConcentrateModel", () => {
  it("uses the Responses API with the bare model slug and safe defaults", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        completedResponse(),
    );
    const model = createConcentrateModel("concentrate:glm-5.3", {
      apiKey: "sk-cn-test",
      fetch: fetchMock,
    });

    const result = await model.doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Say ok" }] }],
      providerOptions: { openai: { reasoningEffort: "high", store: true } },
    } satisfies LanguageModelV3CallOptions);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0];
    expect(call).toBeDefined();
    if (!call) throw new Error("Expected Concentrate fetch call");
    const [url, init] = call;
    expect(String(url)).toBe(`${CONCENTRATE_BASE_URL}/responses`);
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer sk-cn-test",
    );
    expect(JSON.parse(String(init?.body))).toMatchObject({
      model: "glm-5.3",
      store: false,
      reasoning: { effort: "high", summary: "auto" },
      input: [
        {
          role: "user",
          content: [{ type: "input_text", text: "Say ok" }],
        },
      ],
    });
    expect(result.providerMetadata?.concentrate).toMatchObject({
      model: "fireworks/glm-5.3",
      cost: {
        total: 0.000019,
        byok: false,
      },
    });
  });

  it("fails before constructing a request when the key is missing", () => {
    expect(() =>
      createConcentrateModel("concentrate:glm-5.3", { apiKey: " " }),
    ).toThrow(/CONCENTRATE_API_KEY/);
  });

  it("retains billed cost and route metadata on streamed responses", async () => {
    const model = createConcentrateModel("concentrate:glm-5.3", {
      apiKey: "sk-cn-test",
      fetch: vi.fn(async () => streamedResponse()),
    });
    const result = await model.doStream({
      prompt: [{ role: "user", content: [{ type: "text", text: "Say ok" }] }],
    } satisfies LanguageModelV3CallOptions);
    const parts = [];
    const reader = result.stream.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    const finish = parts.find((part) => part.type === "finish");

    expect(finish?.providerMetadata?.concentrate).toMatchObject({
      model: "fireworks/glm-5.3",
      cost: {
        total: 0.000019,
        byok: false,
      },
    });
    expect(parts.some((part) => part.type === "raw")).toBe(false);
  });

  it("rejects non-namespaced and empty model IDs", () => {
    expect(() =>
      createConcentrateModel("glm-5.3", { apiKey: "sk-cn-test" }),
    ).toThrow(/must start/);
    expect(() =>
      createConcentrateModel("concentrate:", { apiKey: "sk-cn-test" }),
    ).toThrow(/cannot be empty/);
  });
});

describe("extractConcentrateResponseMetadata", () => {
  it("reads metadata from completed streaming events", () => {
    expect(
      extractConcentrateResponseMetadata({
        type: "response.completed",
        response: {
          model: "fireworks/glm-5.3",
          cost: {
            total: 0.42,
            byok: false,
            breakdown: {
              "fireworks/glm-5.3": {
                input_tokens: 10,
                output_tokens: 20,
              },
            },
          },
        },
      }),
    ).toEqual({
      model: "fireworks/glm-5.3",
      cost: {
        total: 0.42,
        byok: false,
        breakdown: {
          "fireworks/glm-5.3": {
            input_tokens: 10,
            output_tokens: 20,
          },
        },
      },
    });
  });

  it("rejects malformed cost metadata while retaining the served model", () => {
    expect(
      extractConcentrateResponseMetadata({
        model: "fireworks/glm-5.3",
        cost: { total: "free", byok: false, breakdown: {} },
      }),
    ).toEqual({ model: "fireworks/glm-5.3", cost: undefined });
  });
});

describe("createConcentrateFetch", () => {
  it.each([
    [400, false],
    [401, false],
    [402, false],
    [422, false],
    [424, true],
    [429, true],
    [500, true],
    [503, true],
    [504, true],
  ])("classifies HTTP %i retryable=%s", async (status, retryable) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => {
        return new Response(
          JSON.stringify({
            error: "Upstream request failed",
            message: "Provider unavailable",
            model: "fireworks/glm-5.3",
          }),
          {
            status,
            headers: {
              "retry-after": "2",
              "x-request-id": "req_error",
            },
          },
        );
      },
    );
    const fetchConcentrate = createConcentrateFetch(fetchMock);

    try {
      await fetchConcentrate(`${CONCENTRATE_BASE_URL}/responses`, {
        method: "POST",
        body: '{"sensitive":"not retained on the error"}',
      });
      throw new Error("Expected Concentrate request to fail");
    } catch (error) {
      expect(APICallError.isInstance(error)).toBe(true);
      if (!APICallError.isInstance(error)) return;
      expect(error.message).toBe("Provider unavailable");
      expect(error.statusCode).toBe(status);
      expect(error.isRetryable).toBe(retryable);
      expect(error.responseHeaders?.["retry-after"]).toBe("2");
      expect(error.responseHeaders?.["x-request-id"]).toBe("req_error");
      expect(error.requestBodyValues).toBeUndefined();
    }
  });

  it("passes successful streaming responses through unchanged", async () => {
    const response = completedResponse();
    const fetchConcentrate = createConcentrateFetch(
      vi.fn(
        async (_input: RequestInfo | URL, _init?: RequestInit) => response,
      ) satisfies ConcentrateFetch,
    );

    await expect(
      fetchConcentrate(`${CONCENTRATE_BASE_URL}/responses`),
    ).resolves.toBe(response);
  });
});
