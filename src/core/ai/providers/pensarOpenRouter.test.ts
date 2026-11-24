import { createHash, createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { signGatewayRequest } from "../../auth";
import { createPensarOpenRouterModel } from "./pensarOpenRouter";

afterEach(() => vi.unstubAllGlobals());
describe("Pensar OpenRouter transport", () => {
  it("preserves streamed reasoning, tools, and usage through the real SDK", async () => {
    const chunks = [
      {
        id: "gen-stream",
        choices: [
          {
            index: 0,
            delta: { role: "assistant", reasoning: "thinking" },
            finish_reason: null,
          },
        ],
      },
      {
        id: "gen-stream",
        choices: [
          {
            index: 0,
            delta: {
              tool_calls: [
                {
                  index: 0,
                  id: "call-1",
                  type: "function",
                  function: { name: "ping", arguments: "{}" },
                },
              ],
            },
            finish_reason: null,
          },
        ],
      },
      {
        id: "gen-stream",
        choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
        usage: {
          prompt_tokens: 3,
          completion_tokens: 4,
          total_tokens: 7,
          cost: 0.01,
        },
      },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            `${chunks
              .map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`)
              .join("")}data: [DONE]\n\n`,
            { headers: { "Content-Type": "text/event-stream" } },
          ),
      ),
    );
    const model = createPensarOpenRouterModel("vendor/streamer", {
      apiKey: "pensar-key",
      baseUrl: "https://gateway.example",
    });
    const { stream } = await model.doStream({ prompt: [] });
    const parts = [];
    const reader = stream.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    reader.releaseLock();
    expect(parts).toContainEqual(
      expect.objectContaining({ type: "reasoning-delta", delta: "thinking" }),
    );
    expect(parts).toContainEqual(
      expect.objectContaining({
        type: "tool-call",
        toolName: "ping",
        input: "{}",
      }),
    );
    expect(parts).toContainEqual(
      expect.objectContaining({
        type: "finish",
        usage: expect.objectContaining({
          inputTokens: expect.objectContaining({ total: 3 }),
          outputTokens: expect.objectContaining({ total: 4 }),
        }),
      }),
    );
  });
  it("uses the gateway with refreshed Pensar auth and signs the actual wire body", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        id: "gen-test",
        model: "z-ai/glm-5.3",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "hello" },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const model = createPensarOpenRouterModel("z-ai/glm-5.3", {
      apiKey: "pensar-key",
      baseUrl: "https://gateway.example",
      workspaceId: "ws-1",
      signingKey: "signing-key",
      getToken: async () => ({ token: "fresh-token", type: "workos" }),
    });
    const result = await model.doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "hi" }] }],
      providerOptions: { openrouter: { reasoning: { effort: "high" } } },
    });
    expect(model.modelId).toBe("pensar:z-ai/glm-5.3");
    expect(result.content).toContainEqual(
      expect.objectContaining({ type: "text", text: "hello" }),
    );
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("https://gateway.example/v1/chat/completions");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer fresh-token");
    expect(headers.get("X-Workspace-Id")).toBe("ws-1");
    expect(JSON.parse(init.body as string)).toMatchObject({
      model: "z-ai/glm-5.3",
      reasoning: { effort: "high" },
    });
    expect(headers.get("X-Pensar-Signature")).toBeTruthy();
    // Signature changes with either the selected model or request body.
    expect(
      signGatewayRequest("signing-key", "other/model", init.body as string)
        .signature,
    ).not.toBe(headers.get("X-Pensar-Signature"));
    const payload = `${headers.get("X-Pensar-Timestamp")}\n${headers.get("X-Pensar-Nonce")}\nz-ai/glm-5.3\n${createHash(
      "sha256",
    )
      .update(init.body as string)
      .digest("hex")}`;
    expect(headers.get("X-Pensar-Signature")).toBe(
      createHmac("sha256", "signing-key").update(payload).digest("base64"),
    );
  });
  it("does not contact an upstream when Pensar token refresh fails", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const model = createPensarOpenRouterModel("vendor/new", {
      apiKey: "old",
      baseUrl: "https://gateway.example",
      getToken: async () => null,
    });
    await expect(model.doGenerate({ prompt: [] })).rejects.toThrow(
      "session expired",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
