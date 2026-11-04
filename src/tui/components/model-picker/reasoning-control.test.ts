import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

for (const scenario of [
  "effort",
  "toggle",
  "unknown",
  "compact",
  "inference",
] as const) {
  it(`renders and operates the ${scenario} model picker`, () => {
    const result = spawnSync(
      "bun",
      [join(import.meta.dirname, "__tests__/reasoning-control.tsx"), scenario],
      { encoding: "utf8", timeout: 30000 },
    );
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
  });
}
