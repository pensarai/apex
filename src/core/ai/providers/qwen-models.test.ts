import { afterEach, describe, expect, it, vi } from "vitest";
import { getVisiblePickerModels } from "../../../tui/components/model-picker/model-visibility";
import { resolveExplicitCliModel } from "../../cli/model";
import { getAvailableModels } from "../../providers/utils";
import { getMaxOutputTokens, getModelInfo } from "../models";
import {
  buildModelReasoningOptions,
  getReasoningCapabilities,
  getReasoningChoices,
  type ReasoningSetting,
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

const primeChoices = [
  "default",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
] as const;
const toggleChoices = ["default", "enabled", "disabled"] as const;
const mandatoryChoices = ["default", "low", "medium", "xhigh"] as const;
const noChoices = [] as const;
const fullEffortChoices = [
  "default",
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
] as const;
const binaryEffortChoices = ["default", "none", "medium"] as const;
const flashChoices = [
  "default",
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
] as const;
const basicEffortChoices = [
  "default",
  "none",
  "low",
  "medium",
  "high",
] as const;

const routes = [
  ["qwen/qwen3.8-max-prime", 1_000_000, 131_072, primeChoices],
  ["qwen/qwen3.8-omni-flash", 1_000_000, 131_072, toggleChoices],
  ["qwen/qwen3.8-2.4t-a95b", 1_048_576, 65_536, mandatoryChoices],
  ["qwen/qwen3.7-flash", 1_000_000, 65_536, toggleChoices],
  ["qwen/qwen3.7-plus", 1_000_000, 131_072, toggleChoices],
  ["qwen/qwen3.7-max", 1_000_000, 131_072, toggleChoices],
  ["qwen/qwen3.5-plus-20260420", 1_000_000, 65_536, toggleChoices],
  ["qwen/qwen3.6-flash", 1_000_000, 65_536, toggleChoices],
  ["qwen/qwen3.6-35b-a3b", 262_144, 32_768, toggleChoices],
  ["qwen/qwen3.6-27b", 262_144, 32_768, toggleChoices],
  ["qwen/qwen3.6-plus", 1_000_000, 65_536, toggleChoices],
  ["qwen/qwen3.5-9b", 262_144, 40_960, toggleChoices],
  ["qwen/qwen3.5-35b-a3b", 262_144, 16_384, toggleChoices],
  ["qwen/qwen3.5-27b", 262_144, 65_536, toggleChoices],
  ["qwen/qwen3.5-122b-a10b", 262_144, 65_536, toggleChoices],
  ["qwen/qwen3.5-flash-02-23", 1_000_000, 65_536, toggleChoices],
  ["qwen/qwen3.5-397b-a17b", 262_144, 32_768, toggleChoices],
  ["qwen/qwen3-coder-next", 262_144, 131_072, noChoices],
  ["concentrate:qwen3.5-27b", 262_144, 32_768, fullEffortChoices],
  ["concentrate:qwen3.5-9b", 262_144, 32_768, fullEffortChoices],
  ["concentrate:qwen3.6-27b", 262_144, 32_768, fullEffortChoices],
  ["concentrate:qwen3.7-max", 256_000, 32_768, fullEffortChoices],
  ["concentrate:qwen3.7-plus", 1_000_000, 131_072, binaryEffortChoices],
  ["concentrate:qwen3.7-flash", 1_000_000, 131_072, binaryEffortChoices],
  ["concentrate:qwen3.8-flash", 1_000_000, 131_072, flashChoices],
  ["concentrate:qwen3.8-omni-flash", 1_000_000, 131_072, fullEffortChoices],
  ["concentrate:qwen3.6-plus", 1_000_000, 65_536, binaryEffortChoices],
  ["concentrate:qwen3.6-flash", 1_000_000, 65_536, binaryEffortChoices],
  ["concentrate:qwen3.6-35b", 262_144, 16_384, basicEffortChoices],
  ["concentrate:qwen3.5-122b-a10b", 262_144, 32_768, fullEffortChoices],
  ["concentrate:qwen3.5-plus", 1_000_000, 65_536, binaryEffortChoices],
  ["concentrate:qwen3.5-flash", 1_000_000, 65_536, binaryEffortChoices],
  ["concentrate:qwen3.5-397b-a17b", 262_144, 32_768, fullEffortChoices],
  ["concentrate:qwen3.5-35b-a3b", 262_144, 32_768, fullEffortChoices],
  ["concentrate:qwen3-coder-next", 256_000, 16_384, noChoices],
] as const satisfies readonly (readonly [
  string,
  number,
  number,
  readonly ReasoningSetting[],
])[];

const credentials = {
  responsibleUseAccepted: true,
  openRouterAPIKey: "test-router-key",
  concentrateAPIKey: "sk-cn-test",
};

function completedResponse(openrouter: boolean): Response {
  return Response.json(
    openrouter
      ? {
          id: "chat_qwen",
          created: 1,
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: "ok" },
              finish_reason: "stop",
            },
          ],
          usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 },
        }
      : {
          id: "resp_qwen",
          created_at: 1,
          output: [
            {
              type: "message",
              role: "assistant",
              id: "msg_qwen",
              content: [{ type: "output_text", text: "ok", annotations: [] }],
            },
          ],
          usage: { input_tokens: 12, output_tokens: 8 },
        },
  );
}

describe.each(routes)("Qwen gateway %s", (id, context, budget, choices) => {
  const openrouter = id.startsWith("qwen/");
  const provider = openrouter ? "openrouter" : "concentrate";
  const upstream = id.replace(/^concentrate:/, "");

  it("is selectable with the published limits and reasoning choices", () => {
    expect(getModelInfo(id)).toMatchObject({
      provider,
      contextLength: context,
    });
    expect(
      getVisiblePickerModels(getAvailableModels(credentials)),
    ).toContainEqual(expect.objectContaining({ id, provider }));
    expect(resolveExplicitCliModel({ model: id })).toBe(id);
    expect(getMaxOutputTokens(id)).toBe(budget);
    expect(getReasoningChoices(getReasoningCapabilities(id))).toEqual(choices);
    for (const setting of choices)
      expect(() => buildModelReasoningOptions(id, setting)).not.toThrow();
    for (const setting of [
      "enabled",
      "disabled",
      "none",
      "minimal",
      "low",
      "medium",
      "high",
      "xhigh",
      "max",
    ] as const) {
      if (!choices.some((choice) => choice === setting))
        expect(() => validateReasoningSetting(id, setting)).toThrow(
          "not supported",
        );
    }
  });

  it("serializes the upstream ID, budget, tools, schema and supported reasoning", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        completedResponse(openrouter),
    );
    vi.stubGlobal("fetch", fetchMock);
    const setting = choices.at(-1) ?? "default";
    const result = await getProviderModel(id, credentials).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      maxOutputTokens: budget,
      tools: [
        {
          type: "function",
          name: "check",
          description: "Check",
          inputSchema: {
            type: "object",
            properties: {},
            additionalProperties: false,
          },
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
      providerOptions: buildModelReasoningOptions(id, setting),
    });
    expect(result.content).toContainEqual(
      expect.objectContaining({ type: "text", text: "ok" }),
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected Qwen gateway request");
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
    expect(body.tools).toHaveLength(1);
    expect(openrouter ? body.tools[0].function.name : body.tools[0].name).toBe(
      "check",
    );
    expect(openrouter ? body.response_format.type : body.text.format.type).toBe(
      "json_schema",
    );
    if (setting === "disabled")
      expect(body.reasoning).toMatchObject({ enabled: false });
    else if (setting !== "default")
      expect(body.reasoning).toMatchObject({ effort: setting });
    else expect(body.reasoning).toBeUndefined();
  });
});

it.each([
  ["qwen/qwen3.5-9b", "enabled", { enabled: true }],
  ["concentrate:qwen3.5-9b", "none", { effort: "none" }],
] as const)("sends the alternate reasoning setting for %s", async (id, setting, reasoning) => {
  const openrouter = id.startsWith("qwen/");
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      completedResponse(openrouter),
  );
  vi.stubGlobal("fetch", fetchMock);
  await getProviderModel(id, credentials).doGenerate({
    prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
    providerOptions: buildModelReasoningOptions(id, setting),
  });
  expect(
    JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)).reasoning,
  ).toMatchObject(reasoning);
});
