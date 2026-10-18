import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

for (const scenario of [
  {
    name: "Tab toggles the focused Judge and resets it when Strike turns off",
    mode: "native",
  },
  {
    name: "Tab on Save does not change Strike or Judge",
    mode: "external",
  },
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
