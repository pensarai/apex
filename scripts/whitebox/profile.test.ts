import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { profileRepo } from "./profile";

describe("profileRepo", () => {
  let workDir: string;
  let codebase: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), "wb-profile-"));
    codebase = join(workDir, "codebase");
    mkdirSync(codebase, { recursive: true });
    writeFileSync(join(codebase, "main.py"), "print('hi')\n");
    writeFileSync(join(codebase, "app.ts"), "export const x = 1;\n");
    writeFileSync(
      join(codebase, "package.json"),
      JSON.stringify({ scripts: { build: "tsc", test: "jest" } }),
    );
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it("detects languages, package managers, and build/test scripts", () => {
    const result = profileRepo(codebase);
    expect("error" in result).toBe(false);
    if ("error" in result) return;
    expect(result.path).toBe(codebase);
    expect(result.languages).toEqual(
      expect.arrayContaining(["python", "typescript"]),
    );
    expect(result.packageManagers).toEqual(expect.arrayContaining(["npm"]));
    expect(result.build).toBe("tsc");
    expect(result.test).toBe("jest");
  });

  it("returns a structured error for a missing path", () => {
    const result = profileRepo(join(workDir, "does-not-exist"));
    expect("error" in result).toBe(true);
    if (!("error" in result)) return;
    expect(result.error).toMatch(/does not exist/);
  });
});
