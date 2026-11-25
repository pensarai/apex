import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { getVisiblePickerModels } from "../../../tui/components/model-picker/model-visibility";
import { resolveExplicitCliModel } from "../../cli/model";
import { getAvailableModels } from "../../providers/utils";
import { generateObjectResponse } from "../ai";
import { getMaxOutputTokens, getModelInfo } from "../models";
import {
  buildModelReasoningOptions,
  getReasoningCapabilities,
  getReasoningChoices,
  validateReasoningSetting,
} from "../reasoning";
import { getProviderModel } from "../utils";

vi.mock("undici", async (importOriginal) => {
  const original = await importOriginal<typeof import("undici")>();
  return {
    ...original,
    fetch: (input: RequestInfo | URL, init?: RequestInit) =>
      globalThis.fetch(input, init),
  };
});

afterEach(() => vi.unstubAllGlobals());

const credentials = {
  responsibleUseAccepted: true,
  openRouterAPIKey: "test-router-key",
  concentrateAPIKey: "sk-cn-test",
};

const routes = [
  {
    id: "moonshotai/kimi-k3.1-pro",
    provider: "openrouter",
    budget: 131_072,
    choices: ["default", "none", "low", "high", "max"],
    defaultEffort: "max",
  },
  {
    id: "concentrate:kimi-k3-1-pro",
    provider: "concentrate",
    budget: 32_768,
    choices: ["default", "low", "medium", "high", "xhigh", "max"],
    defaultEffort: "medium",
  },
] as const;

function completion(openrouter: boolean): Response {
  return Response.json(
    openrouter
      ? {
          id: "chat_kimi",
          created: 1,
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
          id: "resp_kimi",
          created_at: 1,
          output: [
            {
              type: "message",
              role: "assistant",
              id: "msg_kimi",
              content: [
                { type: "output_text", text: '{"ok":true}', annotations: [] },
              ],
            },
          ],
          usage: { input_tokens: 12, output_tokens: 8 },
        },
  );
}

describe.each(routes)("Kimi K3.1 Pro via $provider", (route) => {
  const { id, provider, budget, choices, defaultEffort } = route;
  const openrouter = provider === "openrouter";
  const upstream = id.replace(/^concentrate:/, "");

  it("is selectable with the gateway's context, budget and reasoning choices", () => {
    expect(getModelInfo(id)).toMatchObject({
      name: "Kimi K3.1 Pro",
      provider,
      contextLength: 1_048_576,
    });
    expect(
      getVisiblePickerModels(getAvailableModels(credentials)),
    ).toContainEqual(expect.objectContaining({ id, provider }));
    expect(resolveExplicitCliModel({ model: id })).toBe(id);
    expect(getMaxOutputTokens(id)).toBe(budget);
    expect(getReasoningChoices(getReasoningCapabilities(id))).toEqual(choices);
    if (openrouter) {
      for (const setting of ["medium", "xhigh"])
        expect(() => validateReasoningSetting(id, setting)).toThrow(
          "not supported",
        );
    }
  });

  it.each(
    choices,
  )("serializes reasoning=%s alongside the budget and tools", async (setting) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        completion(openrouter),
    );
    vi.stubGlobal("fetch", fetchMock);
    await getProviderModel(id, credentials).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      maxOutputTokens: budget,
      providerOptions: buildModelReasoningOptions(id, setting),
      tools: [
        {
          type: "function",
          name: "check",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      toolChoice: { type: "auto" },
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected Kimi request");
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
    expect(openrouter ? body.max_tokens : body.max_output_tokens).toBe(budget);
    expect(body.reasoning).toMatchObject({
      effort: setting === "default" ? defaultEffort : setting,
    });
    expect(body.tools).toHaveLength(1);
    expect(openrouter ? body.tools[0].function.name : body.tools[0].name).toBe(
      "check",
    );
  });

  it("preserves reasoning through the application's structured-output path", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        completion(openrouter),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect(
      await generateObjectResponse({
        model: id,
        authConfig: credentials,
        prompt: "Check",
        schema: z.object({ ok: z.boolean() }),
        maxTokens: budget,
        reasoning: "high",
      }),
    ).toEqual({ ok: true });
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
    expect(body.model).toBe(upstream);
    expect(body.reasoning).toMatchObject({ effort: "high" });
    expect(openrouter ? body.response_format.type : body.text.format.type).toBe(
      "json_schema",
    );
  });
});
