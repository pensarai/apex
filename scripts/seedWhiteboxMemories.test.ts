import { execSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

describe("whitebox memory seed", () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), "wb-mem-seed-"));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("has unique IDs and all entries tagged whitebox-seed", async () => {
    const { SEEDS } = await import("./seed-whitebox-memories");
    const ids = SEEDS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const seed of SEEDS) {
      expect(seed.tags).toContain("whitebox-seed");
      expect(seed.title).toBeTruthy();
      expect(seed.content.length).toBeGreaterThan(20);
    }
  });

  it("populates the configured data dir and is idempotent", async () => {
    const repoRoot = join(__dirname, "..");
    const script = join(repoRoot, "scripts", "seed-whitebox-memories.ts");
    const env = { ...process.env, PENSAR_DATA_DIR: dataDir };

    const firstOut = execSync(`bun run ${script}`, {
      cwd: repoRoot,
      env,
      encoding: "utf-8",
    });
    expect(firstOut).toMatch(/added/);
    expect(firstOut).not.toMatch(/0 added/);

    const secondOut = execSync(`bun run ${script}`, {
      cwd: repoRoot,
      env,
      encoding: "utf-8",
    });
    expect(secondOut).toMatch(/0 added/);
    expect(secondOut).toMatch(/0 updated/);

    // Verify on-disk file count rather than importing listMemories — the
    // memory module's data-dir resolver binds at import time, before
    // beforeEach can override PENSAR_DATA_DIR.
    const files = readdirSync(join(dataDir, "memories", "framework")).filter(
      (f) => f.endsWith(".json"),
    );
    const { SEEDS } = await import("./seed-whitebox-memories");
    expect(files.length).toBe(SEEDS.length);
  }, 60_000);
});
