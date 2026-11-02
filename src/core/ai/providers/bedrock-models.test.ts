import { afterEach, describe, expect, it, vi } from "vitest";
import { buildReasoningProviderOptions } from "../ai";
import { getProviderModel } from "../utils";

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

describe("Bedrock Claude Opus 5.5", () => {
  const model = "global.anthropic.claude-opus-5-5";

  async function requestBody(
    options: Parameters<typeof buildReasoningProviderOptions>[1],
  ) {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => completion(),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getProviderModel(model, {
      bedrock: { apiKey: "test-key", region: "us-east-1" },
    }).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      providerOptions: buildReasoningProviderOptions(model, options),
    });

    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Bedrock request");
    expect(String(call[0])).toContain(`/model/${model}/converse`);
    return JSON.parse(String(call[1]?.body));
  }

  it("sends adaptive thinking at the documented medium effort by default", async () => {
    expect(await requestBody({ enableThinking: true })).toMatchObject({
      additionalModelRequestFields: {
        thinking: { type: "adaptive", display: "summarized" },
        output_config: { effort: "medium" },
      },
    });
  });

  it("forwards an explicit max effort", async () => {
    expect(
      await requestBody({ enableThinking: true, thinkingEffort: "max" }),
    ).toMatchObject({
      additionalModelRequestFields: { output_config: { effort: "max" } },
    });
  });

  it("keeps thinking on when a caller asks to disable it", async () => {
    const body = await requestBody({ enableThinking: false });
    expect(body.additionalModelRequestFields).toMatchObject({
      thinking: { type: "adaptive", display: "summarized" },
      output_config: { effort: "medium" },
    });
  });
});
