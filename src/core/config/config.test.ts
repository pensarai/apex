import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { get, init, update } from "./config";

let homeDirectory: string;
const originalConcentrateAPIKey = process.env.CONCENTRATE_API_KEY;

beforeEach(() => {
  homeDirectory = mkdtempSync(path.join(os.tmpdir(), "apex-config-test-"));
  vi.spyOn(os, "homedir").mockReturnValue(homeDirectory);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  if (originalConcentrateAPIKey === undefined) {
    delete process.env.CONCENTRATE_API_KEY;
  } else {
    process.env.CONCENTRATE_API_KEY = originalConcentrateAPIKey;
  }
  rmSync(homeDirectory, { recursive: true, force: true });
});

describe("provider environment fallbacks", () => {
  it("loads a Concentrate API key from the environment", async () => {
    process.env.CONCENTRATE_API_KEY = "sk-cn-env";

    const config = await get();

    expect(config.concentrateAPIKey).toBe("sk-cn-env");
  });

  it("discovers the live Hoonify catalog from an environment key without persisting runtime data", async () => {
    vi.stubEnv("HOONIFY_API_KEY", "config-env-key");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        object: "list",
        data: [
          {
            id: "Qwen/Qwen3.6-27B",
            object: "model",
            created: 1,
            owned_by: "hoonify",
          },
        ],
      }),
    );
    const loaded = await get();
    expect(loaded.hoonifyAPIKey).toBe("config-env-key");
    expect(loaded.hoonifyModels).toEqual([
      { id: "Qwen/Qwen3.6-27B", contextLength: 32_768, maxOutputTokens: 4096 },
    ]);
    expect(loaded.hoonifyCatalogError).toBeUndefined();
    await update({
      selectedModelId: "hoonify:Qwen/Qwen3.6-27B",
      hoonifyModels: loaded.hoonifyModels,
    });
    const persisted = JSON.parse(
      readFileSync(path.join(homeDirectory, ".pensar", "config.json"), "utf8"),
    );
    expect(persisted.hoonifyModels).toBeUndefined();
    expect(persisted.hoonifyAPIKey).toBeUndefined();
  });

  it("honors the saved Hoonify key over an environment key and discards a stale catalog", async () => {
    vi.stubEnv("HOONIFY_API_KEY", "must-not-use");
    await init();
    await update({ hoonifyAPIKey: "config-saved-key" });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        data: [{ id: "saved-model", context_window: 32_768 }],
      }),
    );
    const loaded = await get();
    expect(
      new Headers(fetchMock.mock.calls[0][1]?.headers).get("Authorization"),
    ).toBe("Bearer config-saved-key");
    expect(loaded.hoonifyModels?.[0].id).toBe("saved-model");
    await update({ hoonifyAPIKey: "changed-key" });
    fetchMock.mockResolvedValue(new Response("private error", { status: 403 }));
    const failed = await get();
    expect(failed.hoonifyModels).toBeUndefined();
    expect(failed.hoonifyCatalogError).toContain("rejected the API key");
    expect(failed.responsibleUseAccepted).toBe(false);
  });

  it("makes no catalog request when Hoonify is not configured", async () => {
    vi.stubEnv("HOONIFY_API_KEY", "");
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const loaded = await get();
    expect(loaded.hoonifyModels).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("loads custom worker configuration without persisting it or its key", async () => {
    const providers = {
      research: {
        baseUrl: "https://inference.example/v1",
        apiKeyEnv: "APEX_TEST_CUSTOM_KEY",
        models: [
          { id: "test-model", contextLength: 32_000, maxOutputTokens: 4_000 },
        ],
      },
    };
    vi.stubEnv("APEX_CUSTOM_PROVIDERS", JSON.stringify(providers));
    vi.stubEnv("APEX_TEST_CUSTOM_KEY", "test-secret");
    const loaded = await get();
    expect(loaded.customProviders).toEqual(providers);
    expect(JSON.stringify(loaded)).not.toContain("test-secret");
    await update({ selectedModelId: "custom:research:test-model" });
    const persisted = JSON.parse(
      readFileSync(path.join(homeDirectory, ".pensar", "config.json"), "utf8"),
    );
    expect(persisted.customProviders).toBeUndefined();
  });

  it("validates custom providers before persisting configuration", async () => {
    await init();
    await expect(
      update({
        customProviders: { research: { baseUrl: "invalid" } } as never,
      }),
    ).rejects.toThrow("Invalid customProviders");
    expect((await get()).customProviders).toEqual({});
  });
});

describe("Strike Mode config", () => {
  it("defaults to off for a new installation", async () => {
    const config = await init();

    expect(config.strikeMode).toBe(false);
  });

  it("defaults to off when an existing config predates Strike Mode", async () => {
    const configDirectory = path.join(homeDirectory, ".pensar");
    mkdirSync(configDirectory, { recursive: true });
    writeFileSync(
      path.join(configDirectory, "config.json"),
      JSON.stringify({ responsibleUseAccepted: true }),
    );

    const config = await get();

    expect(config.strikeMode).toBe(false);
  });

  it("persists the enabled state across a fresh config load", async () => {
    await init();
    await update({ strikeMode: true });

    vi.resetModules();
    const { get: getReloadedConfig } = await import("./config");
    const reloaded = await getReloadedConfig();

    expect(reloaded.strikeMode).toBe(true);
    const persisted = JSON.parse(
      readFileSync(path.join(homeDirectory, ".pensar", "config.json"), "utf8"),
    ) as { strikeMode?: boolean };
    expect(persisted.strikeMode).toBe(true);
  });
});

describe("recent model config", () => {
  it("persists model history across a fresh config load", async () => {
    await init();
    await update({ recentModelIds: ["model-b", "model-a"] });

    vi.resetModules();
    const { get: getReloadedConfig } = await import("./config");
    const reloaded = await getReloadedConfig();

    expect(reloaded.recentModelIds).toEqual(["model-b", "model-a"]);
  });
});
