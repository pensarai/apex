import { describe, expect, it, beforeEach } from "vitest";
import { existsSync, statSync, readFileSync } from "fs";
import { isAbsolute } from "path";
import {
  getBundledWordlists,
  _resetBundledWordlistsCacheForTests,
} from "./wordlists";

describe("getBundledWordlists", () => {
  beforeEach(() => {
    _resetBundledWordlistsCacheForTests();
  });

  it("resolves to non-null when run from the repo (assets/ is present)", () => {
    const result = getBundledWordlists();
    expect(result).not.toBeNull();
  });

  it("returns absolute paths for all three tiers", () => {
    const result = getBundledWordlists();
    if (result === null) throw new Error("expected non-null wordlists");
    expect(isAbsolute(result.tiny)).toBe(true);
    expect(isAbsolute(result.common)).toBe(true);
    expect(isAbsolute(result.large)).toBe(true);
  });

  it("points at files that exist on disk and are non-empty", () => {
    const result = getBundledWordlists();
    if (result === null) throw new Error("expected non-null wordlists");
    for (const path of [result.tiny, result.common, result.large]) {
      expect(existsSync(path)).toBe(true);
      expect(statSync(path).size).toBeGreaterThan(0);
    }
  });

  it("preserves the size invariant tiny < common < large", () => {
    const result = getBundledWordlists();
    if (result === null) throw new Error("expected non-null wordlists");
    const tinySize = statSync(result.tiny).size;
    const commonSize = statSync(result.common).size;
    const largeSize = statSync(result.large).size;
    expect(tinySize).toBeLessThan(commonSize);
    expect(commonSize).toBeLessThan(largeSize);
  });

  it("keeps tiny.txt in the curated 150-300 line range (catches drift)", () => {
    const result = getBundledWordlists();
    if (result === null) throw new Error("expected non-null wordlists");
    const lines = readFileSync(result.tiny, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(150);
    expect(lines.length).toBeLessThanOrEqual(300);
  });

  it("includes high-signal security paths in tiny.txt", () => {
    const result = getBundledWordlists();
    if (result === null) throw new Error("expected non-null wordlists");
    const content = readFileSync(result.tiny, "utf8");
    const lines = new Set(
      content
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean),
    );
    for (const required of [
      ".env",
      ".git/config",
      ".well-known/security.txt",
      "robots.txt",
      "swagger.json",
      "graphql",
      "wp-config.php",
      "actuator/env",
    ]) {
      expect(lines.has(required)).toBe(true);
    }
  });

  it("caches the result across calls (same object reference)", () => {
    const a = getBundledWordlists();
    const b = getBundledWordlists();
    expect(a).toBe(b);
  });
});
