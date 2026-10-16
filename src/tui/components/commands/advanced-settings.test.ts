import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

for (const scenario of [
  {
    name: "hides and resets the judge when Strike is turned off",
    mode: "native",
  },
  { name: "saves judge off through arrow navigation", mode: "external" },
  { name: "keeps judge choices and Save visible at 60x18", mode: "compact" },
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
