import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

for (const scenario of [
  { name: "keeps the Apex judge when Strike is turned off", mode: "native" },
  { name: "saves judge off for Strike mode", mode: "external" },
] as const) {
  it(scenario.name, () => {
    const result = spawnSync(
      "bun",
      [
        join(import.meta.dirname, "__tests__/advanced-settings-lifecycle.tsx"),
        scenario.mode,
      ],
      { encoding: "utf8", timeout: 30_000 },
    );
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
  });
}
