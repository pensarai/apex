import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import * as config from "./config";
import { getAvailableModels } from "../providers/utils";

let tmpDir: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "config-test-"));
  originalHome = process.env.HOME;
  process.env.HOME = tmpDir;
});

afterEach(() => {
  process.env.HOME = originalHome;
  rmSync(tmpDir, { recursive: true, force: true });
});

/** Write a config JSON directly to the temp config path (simulates cold start) */
function writeConfigToDisk(data: Record<string, unknown>) {
  const configDir = join(tmpDir, ".pensar");
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.json"), JSON.stringify(data));
}

describe("config persistence", () => {
  it("returns default config when no file exists", async () => {
    const cfg = await config.get();
    expect(cfg.responsibleUseAccepted).toBe(false);
    expect(cfg.selectedModelId).toBeUndefined();
  });

  it("persists selectedModelId to disk", async () => {
    await config.init();
    await config.update({
      selectedModelId: "pensar:anthropic.claude-sonnet-4-5-20250929-v1:0",
    });
    const cfg = await config.get();
    expect(cfg.selectedModelId).toBe(
      "pensar:anthropic.claude-sonnet-4-5-20250929-v1:0",
    );
  });

  it("merges without losing existing fields", async () => {
    await config.init();
    await config.update({ anthropicAPIKey: "sk-test-123" });
    await config.update({
      selectedModelId: "claude-haiku-4-5",
    });
    const cfg = await config.get();
    expect(cfg.anthropicAPIKey).toBe("sk-test-123");
    expect(cfg.selectedModelId).toBe("claude-haiku-4-5");
  });

  it("can clear selectedModelId by setting it to null", async () => {
    await config.init();
    await config.update({
      selectedModelId: "pensar:anthropic.claude-opus-4-20250514-v1:0",
    });
    await config.update({ selectedModelId: null });
    const cfg = await config.get();
    expect(cfg.selectedModelId).toBeNull();
  });

  it("reads persisted model selection from disk (cold start)", async () => {
    writeConfigToDisk({
      responsibleUseAccepted: true,
      selectedModelId: "pensar:anthropic.claude-opus-4-20250514-v1:0",
      pensarAPIKey: "pk_test",
    });

    const cfg = await config.get();
    expect(cfg.selectedModelId).toBe(
      "pensar:anthropic.claude-opus-4-20250514-v1:0",
    );
  });
});

describe("model resolution from config", () => {
  it("finds persisted model in available models", async () => {
    const cfg = {
      responsibleUseAccepted: true,
      pensarAPIKey: "pk_test",
      selectedModelId: "pensar:anthropic.claude-sonnet-4-5-20250929-v1:0",
    } satisfies Partial<config.Config> as config.Config;

    const available = getAvailableModels(cfg);
    const saved = available.find((m) => m.id === cfg.selectedModelId);
    expect(saved).toBeDefined();
    expect(saved!.provider).toBe("pensar");
  });

  it("returns undefined when persisted model provider is no longer configured", async () => {
    const cfg = {
      responsibleUseAccepted: true,
      // No pensarAPIKey or accessToken
      selectedModelId: "pensar:anthropic.claude-sonnet-4-5-20250929-v1:0",
    } satisfies Partial<config.Config> as config.Config;

    const available = getAvailableModels(cfg);
    const saved = available.find((m) => m.id === cfg.selectedModelId);
    expect(saved).toBeUndefined();
  });

  it("returns undefined when persisted model ID does not exist", async () => {
    const cfg = {
      responsibleUseAccepted: true,
      pensarAPIKey: "pk_test",
      selectedModelId: "pensar:nonexistent-model-2099",
    } satisfies Partial<config.Config> as config.Config;

    const available = getAvailableModels(cfg);
    const saved = available.find((m) => m.id === cfg.selectedModelId);
    expect(saved).toBeUndefined();
  });
});

describe("model persistence across restart", () => {
  it("persists non-default model across simulated restart", async () => {
    // Session 1: user selects a non-default model
    await config.init();
    await config.update({ pensarAPIKey: "pk_test" });
    const nonDefaultModel = "pensar:anthropic.claude-opus-4-1-20250805-v1:0";
    await config.update({ selectedModelId: nonDefaultModel });

    // Session 2: cold start — read config and check model is restorable
    const cfg = await config.get();
    expect(cfg.selectedModelId).toBe(nonDefaultModel);

    const available = getAvailableModels(cfg);
    const restored = available.find((m) => m.id === cfg.selectedModelId);
    expect(restored).toBeDefined();
    expect(restored!.name).toContain("Opus");
  });

  it("switching models multiple times persists only the latest", async () => {
    await config.init();
    await config.update({ pensarAPIKey: "pk_test" });
    await config.update({
      selectedModelId: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
    });
    await config.update({
      selectedModelId: "pensar:anthropic.claude-sonnet-4-5-20250929-v1:0",
    });
    await config.update({
      selectedModelId: "pensar:anthropic.claude-opus-4-1-20250805-v1:0",
    });

    const cfg = await config.get();
    expect(cfg.selectedModelId).toBe(
      "pensar:anthropic.claude-opus-4-1-20250805-v1:0",
    );
  });

  it("persisted model survives adding a new provider", async () => {
    // User had Anthropic model selected
    await config.init();
    await config.update({
      anthropicAPIKey: "sk-test",
      selectedModelId: "claude-haiku-4-5",
    });

    // Then adds Pensar — the persisted model should NOT be overwritten
    await config.update({ pensarAPIKey: "pk_test" });

    const cfg = await config.get();
    expect(cfg.selectedModelId).toBe("claude-haiku-4-5");
  });
});
