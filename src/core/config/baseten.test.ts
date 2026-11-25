import { afterEach, expect, it, vi } from "vitest";
import { getAvailableModels } from "../providers/utils";
import { discoverBaseten } from "./baseten";
import { resolveCustomModel } from "./customProviders";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
it("lists an owned sleeping deployment through management metadata and makes it selectable", async () => {
  vi.stubEnv("BASETEN_API_KEY", "local-account-test");
  vi.stubEnv("EVALGATE_INFERENCE_GATEWAY_URL", "");
  vi.stubEnv("BASETEN_BASE_URL", "");
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push(url);
      expect(new Headers(init.headers).get("authorization")).toBe(
        "Bearer local-account-test",
      );
      return Response.json(
        url.endsWith("/config")
          ? {
              config: {
                docker_server: {
                  predict_endpoint: "/v1/chat/completions",
                  start_command:
                    "vllm serve /mnt/model --served-model-name private-nyx --max-model-len 262144",
                },
              },
            }
          : {
              models: [
                { id: "owned", name: "Nyx", production_deployment_id: "d1" },
                {
                  id: "empty",
                  name: "No endpoint",
                  production_deployment_id: null,
                },
              ],
            },
      );
    }),
  );
  const providers = await discoverBaseten();
  const id = "custom:baseten-owned-d1:private-nyx";
  expect(
    getAvailableModels({
      responsibleUseAccepted: true,
      customProviders: providers,
    }).find((m) => m.id === id)?.name,
  ).toBe("Baseten / Nyx");
  expect(resolveCustomModel(id, providers)).toMatchObject({
    model: { contextLength: 262144 },
    provider: {
      apiKeyEnv: "BASETEN_API_KEY",
      includeUsage: true,
      baseUrl: "https://model-owned.api.baseten.co/deployment/d1/sync/v1",
    },
  });
  expect(calls).toEqual([
    "https://api.baseten.co/v1/models",
    "https://api.baseten.co/v1/models/owned/deployments/d1/config",
  ]);
});
it("uses only the gateway's attempt identity and authorized catalog even if a local key exists", async () => {
  const deployment = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  vi.stubEnv("BASETEN_API_KEY", "upstream-never-forward");
  vi.stubEnv("EVALGATE_INFERENCE_GATEWAY_URL", "https://gateway.example");
  vi.stubEnv("EVALGATE_INFERENCE_TOKEN", "attempt-fixture");
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toBe("https://gateway.example/v1/models");
    expect(new Headers(init.headers).get("authorization")).toBe(
      "Bearer attempt-fixture",
    );
    return Response.json({
      data: [
        {
          deployment_id: deployment,
          id: "nyx",
          name: "My Nyx",
          context_length: 262144,
          max_output_tokens: 32768,
        },
      ],
    });
  });
  vi.stubGlobal("fetch", fetch);
  const providers = await discoverBaseten();
  expect(
    resolveCustomModel(`custom:baseten-${deployment}:nyx`, providers).provider,
  ).toMatchObject({
    apiKeyEnv: "EVALGATE_INFERENCE_TOKEN",
    baseUrl: `https://gateway.example/deployments/${deployment}/v1`,
  });
  expect(fetch).toHaveBeenCalledOnce();
});
it("never sends a Baseten account key to an untrusted custom endpoint", async () => {
  vi.stubEnv("EVALGATE_INFERENCE_GATEWAY_URL", "");
  vi.stubEnv("BASETEN_BASE_URL", "https://untrusted.example/v1");
  vi.stubEnv("BASETEN_API_KEY", "fixture");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(discoverBaseten()).rejects.toThrow("Baseten HTTPS endpoint");
  expect(fetch).not.toHaveBeenCalled();
});
