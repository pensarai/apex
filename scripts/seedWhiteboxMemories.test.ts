/**
 * Tests for the whitebox memory seed.
 *
 * Validates:
 *   1. The seed array is well-formed (unique IDs, expected tags).
 *   2. Running the seed against an isolated PENSAR_DATA_DIR populates
 *      memories that are then retrievable via list_memories with the
 *      `whitebox-seed` tag.
 *   3. Re-running is idempotent (no duplicates).
 */
import { execSync } from "child_process";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
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

  it("populates ~/.pensar/memories and is idempotent", async () => {
    const repoRoot = join(__dirname, "..");
    const script = join(repoRoot, "scripts", "seed-whitebox-memories.ts");
    const env = { ...process.env, PENSAR_DATA_DIR: dataDir };

    // First run: should add all entries.
    const firstOut = execSync(`bun run ${script}`, {
      cwd: repoRoot,
      env,
      encoding: "utf-8",
    });
    expect(firstOut).toMatch(/added/);
    expect(firstOut).not.toMatch(/0 added/);

    // Second run: everything should be skipped (no --force flag).
    const secondOut = execSync(`bun run ${script}`, {
      cwd: repoRoot,
      env,
      encoding: "utf-8",
    });
    expect(secondOut).toMatch(/0 added/);
    expect(secondOut).toMatch(/0 updated/);

    // Listing memories with the whitebox-seed tag should return the
    // expected count. We avoid importing the listMemories function
    // (which would bind to the test runner's PENSAR_DATA_DIR before
    // we override it); instead, verify the on-disk file count.
    const { readdirSync } = await import("fs");
    const frameworkDir = join(dataDir, "memories", "framework");
    const files = readdirSync(frameworkDir).filter((f) => f.endsWith(".json"));
    const { SEEDS } = await import("./seed-whitebox-memories");
    expect(files.length).toBe(SEEDS.length);
  }, 60_000);
});
