import { afterEach, describe, expect, it, vi } from "vitest";

const { createPensarModel, ensureValidToken, getConfig } = vi.hoisted(() => ({
  createPensarModel: vi.fn((modelId: string, config: unknown) => ({
    specificationVersion: "v3",
    provider: "pensar",
    modelId: `pensar:${modelId}`,
    config,
  })),
  ensureValidToken: vi.fn(),
  getConfig: vi.fn(),
}));

vi.mock("./providers/pensar", () => ({
  createPensarModel,
}));
vi.mock("../auth", () => ({ ensureValidToken }));
vi.mock("../config", () => ({ config: { get: getConfig } }));

import { getProviderModel } from "./utils";

describe("getProviderModel pensar routing", () => {
  const originalEnv = {
    AGENT_API_URL: process.env.AGENT_API_URL,
    AGENT_API_TOKEN: process.env.AGENT_API_TOKEN,
  };

  afterEach(() => {
    createPensarModel.mockClear();
    ensureValidToken.mockReset();
    getConfig.mockReset();
    if (originalEnv.AGENT_API_URL === undefined) {
      delete process.env.AGENT_API_URL;
    } else {
      process.env.AGENT_API_URL = originalEnv.AGENT_API_URL;
    }
    if (originalEnv.AGENT_API_TOKEN === undefined) {
      delete process.env.AGENT_API_TOKEN;
    } else {
      process.env.AGENT_API_TOKEN = originalEnv.AGENT_API_TOKEN;
    }
  });

  it("uses the sandbox Agent API route ahead of persisted gateway/auth config", () => {
    process.env.AGENT_API_URL = "https://stage-api.example.com";
    process.env.AGENT_API_TOKEN = "agent-token";

    const model = getProviderModel("pensar:openai.gpt-5.5", {
      accessToken: "workos-token",
      gatewayUrl: "https://gateway.example.com",
      workspaceId: "workspace-1",
    }) as unknown as { config: Record<string, unknown> };

    expect(model.config.baseUrl).toBe("https://stage-api.example.com/agent");
    expect(model.config.apiKey).toBe("agent-token");
    expect(model.config.getToken).toBeUndefined();
    expect(createPensarModel).toHaveBeenCalledWith(
      "openai.gpt-5.5",
      expect.objectContaining({
        apiKey: "agent-token",
        baseUrl: "https://stage-api.example.com/agent",
      }),
    );
  });

  it("restores a persisted WorkOS session through the token manager", async () => {
    delete process.env.AGENT_API_URL;
    delete process.env.AGENT_API_TOKEN;
    getConfig.mockResolvedValue({
      credentialBackend: "os-vault",
      workosSession: true,
    });
    ensureValidToken.mockResolvedValue({
      token: "restored-token",
      type: "workos",
    });

    const model = getProviderModel("pensar:openai.gpt-5.5", {
      gatewayUrl: "https://gateway.example.com",
      workosSession: true,
      workspaceId: "workspace-1",
    }) as unknown as {
      config: {
        getToken: (options: {
          forceRefresh: boolean;
          rejectedToken: string;
        }) => Promise<unknown>;
      };
    };

    await expect(
      model.config.getToken({
        forceRefresh: true,
        rejectedToken: "old-token",
      }),
    ).resolves.toEqual({ token: "restored-token", type: "workos" });
    expect(ensureValidToken).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialBackend: "os-vault",
        workosSession: true,
      }),
      { forceRefresh: true, rejectedToken: "old-token" },
    );
  });
});
