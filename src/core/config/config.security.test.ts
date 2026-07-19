import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return {
    ...actual,
    default: {
      ...actual,
      homedir: () => process.env.APEX_CONFIG_TEST_HOME ?? actual.homedir(),
    },
  };
});

import { init, update } from "./config";

let homeDir: string;

beforeEach(async () => {
  homeDir = await mkdtemp(path.join(os.tmpdir(), "apex-config-"));
  process.env.APEX_CONFIG_TEST_HOME = homeDir;
});

afterEach(async () => {
  delete process.env.APEX_CONFIG_TEST_HOME;
  await rm(homeDir, { force: true, recursive: true });
});

describe("config persistence", () => {
  it("uses private permissions and atomic queued updates", async () => {
    await init();
    const pensarDir = path.join(homeDir, ".pensar");
    const configFile = path.join(pensarDir, "config.json");

    await Promise.all([
      update({ theme: "midnight" }),
      update({ workspaceId: "workspace-1" }),
    ]);

    const stored = JSON.parse(await readFile(configFile, "utf8"));
    expect(stored).toMatchObject({
      theme: "midnight",
      workspaceId: "workspace-1",
    });
    if (process.platform !== "win32") {
      expect((await stat(pensarDir)).mode & 0o777).toBe(0o700);
      expect((await stat(configFile)).mode & 0o777).toBe(0o600);
    }
  });
});
