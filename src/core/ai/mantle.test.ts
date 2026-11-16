import { afterEach, describe, expect, it, vi } from "vitest";
import { getVisiblePickerModels } from "../../tui/components/model-picker/model-visibility";
import { getAvailableModels, getSavedModelForConfig } from "../providers/utils";
import {
  isMantleResponsesModelId,
  mantleBaseUrl,
  stripMantlePrefix,
} from "./mantle";
import { getMaxOutputTokens, getModelInfo } from "./models";
import {
  buildModelReasoningOptions,
  getReasoningCapabilities,
} from "./reasoning";
import { getProviderModel } from "./utils";

const sol = "mantle:openai.gpt-6.1-sol";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("GPT 6.1 Sol on Bedrock Mantle", () => {
  it("is selectable and restores a saved selection with a Bedrock key", () => {
    const config = {
      responsibleUseAccepted: true,
      bedrockAPIKey: "test-key",
      selectedModelId: sol,
    };
    expect(getVisiblePickerModels(getAvailableModels(config))).toContainEqual(
      expect.objectContaining({ id: sol, provider: "bedrock-mantle" }),
    );
    expect(getSavedModelForConfig(config)?.id).toBe(sol);
    expect(
      getAvailableModels({ responsibleUseAccepted: true }),
    ).not.toContainEqual(expect.objectContaining({ id: sol }));
    expect(getModelInfo(sol).contextLength).toBe(1_000_000);
    expect(getMaxOutputTokens(sol)).toBe(128_000);
    expect(isMantleResponsesModelId(sol)).toBe(true);
    expect(getReasoningCapabilities(sol)).toMatchObject({
      control: "effort",
      efforts: ["low", "medium", "high", "xhigh", "max"],
      canDisable: false,
    });
  });

  it.each([
    undefined,
    "low",
    "max",
  ] as const)("sends %s effort, tools and the output budget to the us-east-1 Responses endpoint", async (effort) => {
    vi.stubEnv("BEDROCK_MANTLE_REGION", "");
    vi.stubEnv("AWS_REGION", "eu-west-1");
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        Response.json({
          id: "resp_test",
          created_at: 1,
          model: "openai.gpt-6.1-sol",
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
    const result = await getProviderModel(sol, {
      bedrock: { apiKey: "test-key" },
    }).doGenerate({
      prompt: [{ role: "user", content: [{ type: "text", text: "Check" }] }],
      maxOutputTokens: getMaxOutputTokens(sol),
      temperature: 0.2,
      tools: [
        {
          type: "function",
          name: "check",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      providerOptions: effort
        ? buildModelReasoningOptions(sol, effort)
        : undefined,
    });
    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("Expected a Mantle request");
    expect(String(call[0])).toBe(
      "https://bedrock-mantle.us-east-1.api.aws/openai/v1/responses",
    );
    expect(new Headers(call[1]?.headers).get("authorization")).toBe(
      "Bearer test-key",
    );
    const body = JSON.parse(String(call[1]?.body));
    expect(body).toMatchObject({
      model: "openai.gpt-6.1-sol",
      max_output_tokens: 128_000,
      reasoning: { effort: effort ?? "medium" },
      tools: [{ type: "function", name: "check" }],
    });
    expect(body.temperature).toBeUndefined();
    expect(result.content).toContainEqual(
      expect.objectContaining({
        type: "tool-call",
        toolName: "check",
        toolCallId: "call_test",
        input: "{}",
      }),
    );
  });

  it.each([
    [sol, "us-east-1"],
    ["mantle:openai.gpt-5.5", "us-east-2"],
  ])("preserves the model region and an explicit override for %s", async (id, region) => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(new Uint8Array()),
    );
    vi.stubGlobal("fetch", fetchMock);
    for (const override of ["", "us-west-2"]) {
      vi.stubEnv("BEDROCK_MANTLE_REGION", override);
      await getProviderModel(id, { bedrock: { apiKey: "test-key" } }).doStream({
        prompt: [],
      });
      expect(String(fetchMock.mock.lastCall?.[0])).toBe(
        `https://bedrock-mantle.${override || region}.api.aws/openai/v1/responses`,
      );
    }
  });

  it("signs credential-provider requests for the model's region", async () => {
    vi.stubEnv("BEDROCK_MANTLE_REGION", "");
    vi.stubEnv("BEDROCK_API_KEY", "");
    vi.stubEnv("AWS_BEARER_TOKEN_BEDROCK", "");
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(new Uint8Array()),
    );
    vi.stubGlobal("fetch", fetchMock);
    await getProviderModel(sol, {
      bedrock: {
        credentialProvider: async () => ({
          accessKeyId: "fixture-access-key",
          secretAccessKey: "fixture-secret-key",
          sessionToken: "fixture-session-token",
        }),
      },
    }).doStream({ prompt: [] });
    const headers = new Headers(fetchMock.mock.lastCall?.[1]?.headers);
    expect(headers.get("authorization")).toContain(
      "/us-east-1/bedrock-mantle/aws4_request",
    );
    expect(headers.get("x-amz-security-token")).toBe("fixture-session-token");
  });
});

describe("apex mantle helpers", () => {
  it("detects mantle routing ids and Responses-API models", () => {
    expect(isMantleResponsesModelId("openai.gpt-5.5")).toBe(true);
    expect(isMantleResponsesModelId("mantle:openai.gpt-5.5")).toBe(true);
    expect(isMantleResponsesModelId("openai.gpt-oss-120b")).toBe(false);
    expect(stripMantlePrefix("mantle:openai.gpt-5.5")).toBe("openai.gpt-5.5");
  });

  it("builds the /openai/v1 base url", () => {
    expect(mantleBaseUrl("us-east-2")).toBe(
      "https://bedrock-mantle.us-east-2.api.aws/openai/v1",
    );
  });
});

describe("mantle model registry", () => {
  it("maps the routed id to the bedrock-mantle provider", () => {
    const info = getModelInfo("mantle:openai.gpt-5.5");
    expect(info.provider).toBe("bedrock-mantle");
    expect(info.contextLength).toBe(272000);
  });

  it("uses a 128K output budget for GPT 5.5", () => {
    expect(getMaxOutputTokens("mantle:openai.gpt-5.5")).toBe(128000);
  });

  it("routes the gateway id to the pensar provider", () => {
    expect(getModelInfo("pensar:openai.gpt-5.5").provider).toBe("pensar");
  });
});

describe("getProviderModel bedrock-mantle case", () => {
  it("builds a Mantle Responses model for the routed id", () => {
    const model = getProviderModel("mantle:openai.gpt-5.5", {}) as unknown as {
      modelId: string;
      provider: string;
    };
    expect(model.modelId).toBe("openai.gpt-5.5");
    expect(model.provider).toContain("mantle");
  });
});
