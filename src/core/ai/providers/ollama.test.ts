import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildUsageFooterLabels } from "../../../tui/components/usage-labels";
import { SessionUsageStore } from "../../../tui/context/session-usage";
import { resolveExplicitCliModel } from "../../cli/model";
import { discoverOllama, type OllamaCatalog } from "../../ollama";
import {
  getAvailableModels,
  getDefaultModelForConfig,
  getSavedModelForConfig,
  hasAnyProviderConfigured,
} from "../../providers/utils";
import { getContextWindow, normalizeStepUsage, streamResponse } from "../ai";
import { getMaxOutputTokens, getModelInfo } from "../models";
import { getReasoningCapabilities } from "../reasoning";
import { buildAuthConfig, getProviderModel } from "../utils";

const upstreamId = "hf.co/webAI-Official/TwIL-8B:TwIL-8B-Q4_K_M-balanced.gguf";
const id = `ollama:${upstreamId}`;
const ollama: OllamaCatalog = {
  baseURL: "http://127.0.0.1:11434",
  models: [
    {
      id: upstreamId,
      contextLength: 32_768,
      maxOutputTokens: 4_096,
      running: true,
    },
  ],
};

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("auto-discovered Ollama inference", () => {
  it("is available without a key, preserves saved choices, and keeps manual local endpoints", () => {
    const config = { responsibleUseAccepted: true, ollama };
    expect(hasAnyProviderConfigured(config)).toBe(true);
    expect(hasAnyProviderConfigured({ ...config, ollama: undefined })).toBe(
      false,
    );
    expect(getAvailableModels(config)).toEqual([
      { id, name: upstreamId, provider: "ollama", contextLength: 32_768 },
    ]);
    expect(getDefaultModelForConfig(config)?.id).toBe(id);
    expect(
      getDefaultModelForConfig({ ...config, anthropicAPIKey: "key" })?.provider,
    ).toBe("anthropic");
    expect(getSavedModelForConfig({ ...config, selectedModelId: id })?.id).toBe(
      id,
    );
    expect(
      getSavedModelForConfig({
        responsibleUseAccepted: true,
        selectedModelId: id,
        anthropicAPIKey: "key",
      })?.id,
    ).toBe(id);
    expect(
      getAvailableModels({
        ...config,
        localModelName: upstreamId,
        localModelUrl: "http://localhost:1234/v1",
      }).map((model) => model.id),
    ).toEqual([upstreamId, id]);
    expect(getModelInfo(id).provider).toBe("ollama");
    expect(getContextWindow(id, undefined, undefined, ollama)).toBe(32_768);
    expect(getMaxOutputTokens(id, undefined, undefined, ollama)).toBe(4_096);
    expect(getReasoningCapabilities("ollama:gpt-5").control).toBe("none");
    expect(
      resolveExplicitCliModel({
        model: upstreamId,
        provider: "ollama",
        ollama,
      }),
    ).toBe(id);
    expect(resolveExplicitCliModel({ model: id, ollama })).toBe(id);
    expect(
      resolveExplicitCliModel({
        model: "manual-model",
        provider: "ollama",
        ollama,
        customProviders: {
          ollama: {
            baseUrl: "http://localhost:1234/v1",
            models: [
              {
                id: "manual-model",
                contextLength: 32_768,
                maxOutputTokens: 4_096,
              },
            ],
          },
        },
      }),
    ).toBe("custom:ollama:manual-model");
    expect(() =>
      resolveExplicitCliModel({ model: "ollama:unknown", ollama }),
    ).toThrow("unavailable");
    expect(() => getProviderModel(id)).toThrow("Start Ollama");
    expect(() => getProviderModel("ollama:unknown", { ollama })).toThrow(
      "unavailable",
    );
  });

  it.each([
    true,
    false,
  ])("streams local inference into footer totals without cloud credentials (usage available: %s)", async (reportsUsage) => {
    vi.stubEnv("OPENAI_API_KEY", "must-not-forward");
    vi.stubEnv("LOCAL_MODEL_URL", "http://wrong-endpoint.invalid/v1");
    const requests: {
      url?: string;
      authorization?: string;
      body: Record<string, unknown>;
    }[] = [];
    const server = createServer(async (req, res) => {
      if (req.url === "/api/tags" || req.url === "/api/ps") {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            models: [{ name: upstreamId, context_length: 32_768 }],
          }),
        );
        return;
      }
      let body = "";
      for await (const chunk of req) body += chunk;
      const requestBody = JSON.parse(body);
      requests.push({
        url: req.url,
        authorization: req.headers.authorization,
        body: requestBody,
      });
      res.setHeader("content-type", "text/event-stream");
      res.write(
        `data: ${JSON.stringify({
          id: "probe",
          model: upstreamId,
          choices: [
            { index: 0, delta: { content: "LOCAL_OK" }, finish_reason: "stop" },
          ],
        })}\n\n`,
      );
      if (reportsUsage && requestBody.stream_options?.include_usage) {
        res.write(
          `data: ${JSON.stringify({
            id: "probe",
            model: upstreamId,
            choices: [],
            usage: {
              prompt_tokens: 123,
              completion_tokens: 45,
              total_tokens: 168,
            },
          })}\n\n`,
        );
      }
      res.end("data: [DONE]\n\n");
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    try {
      vi.stubEnv(
        "OLLAMA_HOST",
        `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      );
      const discovered = await discoverOllama();
      const config = { responsibleUseAccepted: true, ollama: discovered };
      const selected = getDefaultModelForConfig(config);
      if (!selected) throw new Error("No Ollama model available");
      const usageStore = new SessionUsageStore();
      usageStore.enterSession("ollama-session");
      const onStepFinish = vi.fn((step) => {
        usageStore.addSessionTokens("ollama-session", normalizeStepUsage(step));
      });
      for (const turn of [1, 2]) {
        const response = streamResponse({
          model: selected.id,
          authConfig: buildAuthConfig(config),
          prompt: "Say LOCAL_OK",
          onStepFinish,
          silent: true,
        });
        for await (const part of response.fullStream) {
          if (part.type === "error") throw part.error;
        }
        expect(await response.text).toBe("LOCAL_OK");
        expect(onStepFinish).toHaveBeenCalledTimes(turn);
        const expectedInput = reportsUsage ? 123 * turn : 0;
        const expectedOutput = reportsUsage ? 45 * turn : 0;
        const usage = usageStore.getActiveSnapshot();
        expect(usage.tokenUsage).toMatchObject({
          inputTokens: expectedInput,
          outputTokens: expectedOutput,
        });
        expect(
          buildUsageFooterLabels({ ...usage, width: 120 }).tokensLabel,
        ).toBe(`in ${expectedInput}  out ${expectedOutput}`);
      }
      expect(requests).toHaveLength(2);
      expect(requests[0]).toMatchObject({
        url: "/v1/chat/completions",
        authorization: undefined,
        body: {
          model: upstreamId,
          stream: true,
          max_tokens: 4_096,
          stream_options: { include_usage: true },
        },
      });
      expect(requests[0].body).not.toHaveProperty("reasoning_effort");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      });
    }
  });
});
