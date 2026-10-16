import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it("saves an external finding policy independently of Strike mode", () => {
  const result = spawnSync(
    "bun",
    [join(import.meta.dirname, "__tests__/advanced-settings-lifecycle.tsx")],
    { encoding: "utf8", timeout: 30_000 },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
