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
