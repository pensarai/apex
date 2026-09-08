import {
  APICallError,
  type LanguageModelV3CallOptions,
} from "@ai-sdk/provider";
import { describe, expect, it, vi } from "vitest";
import {
  CONCENTRATE_BASE_URL,
  createConcentrateFetch,
  createConcentrateModel,
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

describe("createConcentrateModel", () => {
  it("uses the Responses API with the bare model slug and safe defaults", async () => {
    const fetchMock = vi.fn(async () => completedResponse());
    const model = createConcentrateModel("concentrate:glm-5.3", {
      apiKey: "sk-cn-test",
      fetch: fetchMock as typeof fetch,
    });

    await model.doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Say ok" }] }],
      providerOptions: { openai: { reasoningEffort: "high", store: true } },
    } satisfies LanguageModelV3CallOptions);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`${CONCENTRATE_BASE_URL}/responses`);
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer sk-cn-test",
    );
    expect(JSON.parse(String(init?.body))).toMatchObject({
      model: "glm-5.3",
      store: false,
      reasoning: { effort: "high" },
      input: [{ role: "user", content: "Say ok" }],
    });
  });

  it("fails before constructing a request when the key is missing", () => {
    expect(() =>
      createConcentrateModel("concentrate:glm-5.3", { apiKey: " " }),
    ).toThrow(/CONCENTRATE_API_KEY/);
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
    const fetchMock = vi.fn(async () => {
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
    });
    const fetchConcentrate = createConcentrateFetch(
      fetchMock as typeof fetch,
    );

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
      vi.fn(async () => response) as typeof fetch,
    );

    await expect(
      fetchConcentrate(`${CONCENTRATE_BASE_URL}/responses`),
    ).resolves.toBe(response);
  });
});
