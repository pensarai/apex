import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return path.endsWith(".ts") && !path.endsWith(".test.ts") ? [path] : [];
  });
}

describe("production prompt isolation", () => {
  it("keeps benchmark suite identifiers out of production agent sources", () => {
    const roots = [
      join(import.meta.dirname, "..", "agents"),
      import.meta.dirname,
    ];
    const forbidden = [
      /\bargus\b/i,
      /\bxben-\d/i,
      /\bpacebench\b/i,
      /\bfullchain\d/i,
    ];
    const violations = roots.flatMap((root) =>
      sourceFiles(root).flatMap((path) => {
        if (
          path.includes("/specialized/benchmark/") ||
          path.endsWith("/benchmarkComparisonAgent.ts")
        ) {
          return [];
        }
        const content = readFileSync(path, "utf8");
        return forbidden.some((pattern) => pattern.test(content)) ? [path] : [];
      }),
    );
    expect(violations).toEqual([]);
  });
});
