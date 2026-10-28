import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  buildReasoningProviderOptions,
  generateObjectResponse,
  streamResponse,
} from "./ai";
import { AVAILABLE_MODELS } from "./models";
import openRouterSnapshot from "./models/openrouter-reasoning.json";
import { convertToBedrockFormat } from "./providers/pensarFormatters";
import {
  buildModelReasoningOptions,
  getReasoningCapabilities,
  getReasoningChoices,
  validateReasoningSetting,
} from "./reasoning";
import {
  consumeStream,
  createSummarizationStream,
  getProviderModel,
} from "./utils";

afterEach(() => vi.unstubAllGlobals());

describe("model reasoning capabilities", () => {
  it.each([
    ["gpt-6.1-sol", "effort", false],
    ["gpt-6.1-terra", "effort", false],
    ["concentrate:gpt-6.1-terra", "effort", false],
    ["concentrate:kimi-k3-1-pro", "effort", false],
    ["claude-opus-5-5", "effort", false],
    ["claude-sonnet-4-5", "toggle", true],
    ["gemini-3-pro-preview", "effort", false],
    ["gemini-2.5-flash", "toggle", true],
    ["gemini-2.5-pro", "none", false],
    ["claude-future-99", "none", false],
    ["local", "none", false],
  ])("exposes the supported control for %s", (model, control, canDisable) => {
    expect(getReasoningCapabilities(model as string)).toMatchObject({
      control,
      canDisable,
    });
  });

  it("has a valid request for every displayed choice in the built-in catalog", () => {
    for (const model of AVAILABLE_MODELS) {
      const cap = getReasoningCapabilities(model.id);
      const choices = getReasoningChoices(cap);
      if (cap.alwaysOn) expect(choices).not.toContain("disabled");
      for (const choice of choices)
        expect(() =>
          buildModelReasoningOptions(model.id, choice),
        ).not.toThrow();
      if (model.provider === "openrouter")
        expect(Object.hasOwn(openRouterSnapshot.models, model.id)).toBe(true);
    }
  });

  it("does not invent levels or permit mandatory thinking to be disabled", () => {
    for (const [model, setting] of [
      ["gpt-6.1-sol", "none"],
      ["gpt-6.1-terra", "none"],
      ["claude-opus-5-5", "disabled"],
      ["gemini-3-pro-preview", "medium"],
      ["gpt-5.6-sol", "ultra"],
      ["unknown", "high"],
    ]) {
      expect(() => validateReasoningSetting(model, setting)).toThrow(
        "not supported",
      );
    }
    expect(buildModelReasoningOptions("unknown", "default")).toBeUndefined();
  });

  it("uses the route's published levels instead of guessing from a model family", () => {
    expect(
      getReasoningChoices(getReasoningCapabilities("z-ai/glm-5.3")),
    ).toEqual(["default", "low", "high", "max"]);
    expect(buildModelReasoningOptions("z-ai/glm-5.3", "default")).toMatchObject(
      { openrouter: { reasoning: { effort: "max", enabled: true } } },
    );
  });

  it("requires declared capabilities for custom endpoints", () => {
    expect(getReasoningCapabilities("custom:removed:model", {}).control).toBe(
      "none",
    );
    const provider = {
      baseUrl: "https://example.test/v1",
      apiType: "responses" as const,
      apiKeyEnv: "TEST_KEY",
      models: [{ id: "unknown", contextLength: 32000, maxOutputTokens: 8000 }],
    };
    expect(
      getReasoningCapabilities("custom:test:unknown", { test: provider })
        .control,
    ).toBe("none");
    const customProviders = {
      test: {
        ...provider,
        models: [
          {
            ...provider.models[0],
            supportedReasoningEfforts: ["low", "high"] as ["low", "high"],
          },
        ],
      },
    };
    expect(
      buildModelReasoningOptions("custom:test:unknown", "high", {
        customProviders,
      }),
    ).toMatchObject({
      openai: { reasoningEffort: "high", forceReasoning: true },
    });
  });

  it("bounds legacy thinking budgets to the actual response limit", () => {
    expect(
      buildReasoningProviderOptions("claude-sonnet-4-5", {
        reasoning: "enabled",
        maxOutputTokens: 4096,
      }),
    ).toMatchObject({
      anthropic: { thinking: { type: "enabled", budgetTokens: 2048 } },
    });
    expect(() =>
      buildReasoningProviderOptions("claude-sonnet-4-5", {
        reasoning: "enabled",
        maxOutputTokens: 1024,
      }),
    ).toThrow("output limit");
  });

  it("preserves legacy thinking choices for older OpenRouter Claude models", () => {
    expect(
      buildModelReasoningOptions("anthropic/claude-sonnet-4.5", "default"),
    ).toBeUndefined();
    expect(
      buildReasoningProviderOptions("anthropic/claude-opus-4.6", {}),
    ).toMatchObject({
      openrouter: { reasoning: { enabled: false, effort: "none" } },
    });
    expect(
      buildReasoningProviderOptions("anthropic/claude-opus-4.6", {
        enableThinking: true,
      }),
    ).toMatchObject({
      openrouter: { reasoning: { enabled: true, effort: "high" } },
    });
    expect(
      buildReasoningProviderOptions("anthropic/claude-sonnet-4.5", {
        enableThinking: true,
      }),
    ).toMatchObject({ openrouter: { reasoning: { enabled: true } } });
  });

  it("preserves adaptive effort in Pensar's gateway request", () => {
    const body = convertToBedrockFormat("anthropic.claude-opus-4-8", {
      prompt: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
      providerOptions: buildModelReasoningOptions(
        "pensar:anthropic.claude-opus-4-8",
        "low",
      ),
    });
    expect(body).toMatchObject({
      thinking: { type: "adaptive", display: "summarized" },
      output_config: { effort: "low" },
    });
  });

  it("preserves effort in Pensar's Responses gateway request", () => {
    expect(
      convertToBedrockFormat("openai.gpt-5.5", {
        prompt: [],
        providerOptions: buildModelReasoningOptions(
          "pensar:openai.gpt-5.5",
          "low",
        ),
      }),
    ).toMatchObject({ reasoning: { effort: "low" } });
  });
});

describe("reasoning request serialization", () => {
  it("retains effort alongside provider routing through streaming and compaction", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init?: RequestInit) => {
        bodies.push(JSON.parse(String(init?.body)));
        const chunk = {
          id: "test",
          created: 0,
          model: "z-ai/glm-5.3",
          choices: [
            { index: 0, delta: { content: "done" }, finish_reason: "stop" },
          ],
          usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
        };
        return new Response(
          `data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`,
          { headers: { "content-type": "text/event-stream" } },
        );
      }),
    );
    const opts = {
      model: "z-ai/glm-5.3",
      reasoning: "low" as const,
      prompt: "hello",
      tools: {},
      authConfig: { openRouterAPIKey: "test" },
      silent: true,
    };
    await consumeStream(streamResponse(opts), {});
    await consumeStream(
      createSummarizationStream(
        [{ role: "user", content: "hello" }],
        opts,
        getProviderModel(opts.model, opts.authConfig),
      ),
      {},
    );
    expect(bodies.length).toBeGreaterThanOrEqual(3);
    for (const body of bodies)
      expect(body).toMatchObject({
        reasoning: { effort: "low", enabled: true },
        provider: { only: ["z-ai"], allow_fallbacks: false },
      });
  });

  it.each([
    ["gpt-6.1-sol", "low", { reasoning: { effort: "low" } }],
    [
      "claude-opus-5-5",
      "low",
      { thinking: { type: "adaptive" }, output_config: { effort: "low" } },
    ],
    [
      "claude-sonnet-4-5",
      "enabled",
      { thinking: { type: "enabled", budget_tokens: 10000 } },
    ],
    ["z-ai/glm-5.3", "high", { reasoning: { effort: "high" } }],
    [
      "gemini-3.1-pro-preview",
      "low",
      { generationConfig: { thinkingConfig: { thinkingLevel: "low" } } },
    ],
    [
      "gemini-2.5-flash",
      "disabled",
      { generationConfig: { thinkingConfig: { thinkingBudget: 0 } } },
    ],
  ] as const)("serializes the selected setting for %s", async (id, setting, expected) => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ error: { message: "Captured request" } }),
          { status: 400 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const model = getProviderModel(id, {
      openAiAPIKey: "test",
      anthropicAPIKey: "test",
      googleAPIKey: "test",
      openRouterAPIKey: "test",
    });
    await expect(
      model.doGenerate({
        prompt: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
        maxOutputTokens: 16000,
        providerOptions: buildReasoningProviderOptions(id, {
          reasoning: setting,
        }),
      }),
    ).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(
      JSON.parse(
        String(
          (fetchMock.mock.calls[0] as unknown as [unknown, RequestInit])[1]
            .body,
        ),
      ),
    ).toMatchObject(expected);
  });

  it("forwards effort through structured generation", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ error: { message: "Captured request" } }),
          { status: 400 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      generateObjectResponse({
        model: "claude-opus-5-5",
        reasoning: "low",
        schema: z.object({ ok: z.boolean() }),
        prompt: "hello",
        authConfig: { anthropicAPIKey: "test" },
      }),
    ).rejects.toThrow();
    expect(
      JSON.parse(
        String(
          (fetchMock.mock.calls[0] as unknown as [unknown, RequestInit])[1]
            .body,
        ),
      ),
    ).toMatchObject({ output_config: { effort: "low" } });
  });
});
