import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

for (const scenario of [
  { name: "selects Default v2", mode: "default-v2" },
  { name: "restores Default v2", mode: "resume-default-v2" },
  {
    name: "keeps Default v2 controls visible at 60x18",
    mode: "default-v2-compact",
  },
  {
    name: "saves fractional seconds as integer milliseconds",
    mode: "lance-time",
  },
  { name: "selects Lance and independently enables its judge", mode: "lance" },
  {
    name: "keeps the Lance selector, judge, and Save visible at 60x18",
    mode: "lance-compact",
  },
  {
    name: "preserves the judge setting while cycling execution modes",
    mode: "native",
  },
  {
    name: "Tab on Save does not change Strike or Judge",
    mode: "external",
  },
  { name: "keeps judge choices and Save visible at 60x18", mode: "compact" },
  { name: "restores a saved Lance judge preference", mode: "resume-lance" },
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
