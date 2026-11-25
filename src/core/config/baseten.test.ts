import { afterEach, expect, it, vi } from "vitest";
import { getAvailableModels } from "../providers/utils";
import { discoverBaseten, usesBasetenEndpoint } from "./baseten";
import { resolveCustomModel } from "./customProviders";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
const serve = "vllm serve /mnt/model --served-model-name private-nyx";
it.each([
  [`${serve} --max-model-len 262144`, 262_144],
  [`${serve} --max-model-len 32K`, 32_768],
  [`${serve} --max-model-len 32768;`, 32_768],
  [`${serve} --max-model-len 25.6k`, 25_600],
  [
    `echo "previous --served-model-name old --max-model-len 32768)"; exec ${serve} --max-model-len="8192"`,
    8192,
  ],
  [
    `echo 'vllm serve --served-model-name old --max-model-len 32768'; ${serve}`,
    undefined,
  ],
  [`/bin/sh -c 'echo ready && exec uv run ${serve} --max-model-len 8K'`, 8192],
  [
    `bash -e -c 'if test -d /mnt/model; then exec -- ${serve} --max-model-len 8K; fi'`,
    8192,
  ],
  [`bash -ce 'uv run -- ${serve} --max-model-len 8K'`, 8192],
  [`bash -ec -- '${serve} --max-model-len 8K'`, 8192],
  [`${serve} --max-model-len 8K || ${serve} --max-model-len 8192`, 8192],
  [`${serve} --max-model-len 32K || ${serve} --max-model-len 8K`, undefined],
  [
    `if ! ${serve} --max-model-len 32K; then ${serve} --max-model-len 8K; fi`,
    undefined,
  ],
  [
    `if test -d /mnt/base; then vllm serve /mnt/base; else ${serve} --max-model-len 8K; fi`,
    undefined,
  ],
] as const)("discovers the serving arguments in %s without waking the deployment", async (command, expected) => {
  const key = `local-account-test-${encodeURIComponent(command)}`;
  vi.stubEnv("BASETEN_API_KEY", key);
  vi.stubEnv("BASETEN_BASE_URL", "");
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push(url);
      expect(new Headers(init.headers).get("authorization")).toBe(
        `Bearer ${key}`,
      );
      return Response.json(
        url.endsWith("/config")
          ? {
              config: {
                docker_server: {
                  predict_endpoint: "/v1/chat/completions",
                  start_command: command,
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
  expect(calls).toEqual([
    "https://api.baseten.co/v1/models",
    "https://api.baseten.co/v1/models/owned/deployments/d1/config",
  ]);
  if (expected === undefined) {
    expect(providers).toEqual({});
    return;
  }
  const id = "custom:baseten-owned-d1:private-nyx";
  expect(
    getAvailableModels({
      responsibleUseAccepted: true,
      customProviders: providers,
    }).find((m) => m.id === id)?.name,
  ).toBe("Baseten / Nyx");
  expect(resolveCustomModel(id, providers)).toMatchObject({
    model: { contextLength: expected },
    provider: {
      apiKeyEnv: "BASETEN_API_KEY",
      includeUsage: true,
      baseUrl: "https://model-owned.api.baseten.co/deployment/d1/sync/v1",
    },
  });
});
it("recognizes explicitly labelled Baseten proxies without depending on the credential variable", async () => {
  vi.stubEnv("BASETEN_API_KEY", "");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const providers = {
    research: {
      name: "Baseten deployment",
      baseUrl: "https://proxy.example/team/v1",
      apiKeyEnv: "TEAM_MODEL_TOKEN",
      models: [{ id: "nyx", contextLength: 262144, maxOutputTokens: 32768 }],
    },
  };
  expect(usesBasetenEndpoint("custom:research:nyx", providers)).toBe(true);
  expect(
    usesBasetenEndpoint("custom:baseten-research:nyx", {
      "baseten-research": { ...providers.research, name: "Research" },
    }),
  ).toBe(false);
  expect(await discoverBaseten()).toEqual({});
  expect(fetch).not.toHaveBeenCalled();
});
it.each([
  "https://untrusted.example/v1",
  "https://inference.baseten.co:8443/v1",
])("rejects %s before sending a Baseten account key", async (endpoint) => {
  vi.stubEnv("BASETEN_BASE_URL", endpoint);
  vi.stubEnv("BASETEN_API_KEY", "fixture");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(discoverBaseten()).rejects.toThrow("Baseten HTTPS endpoint");
  expect(fetch).not.toHaveBeenCalled();
});
