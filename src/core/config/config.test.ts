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

beforeEach(() => {
  homeDirectory = mkdtempSync(path.join(os.tmpdir(), "apex-config-test-"));
  vi.spyOn(os, "homedir").mockReturnValue(homeDirectory);
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(homeDirectory, { recursive: true, force: true });
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
