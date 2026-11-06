import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it("renders model loading separately from compaction and disposes its animation", () => {
  const result = spawnSync(
    "bun",
    [join(import.meta.dirname, "__tests__/model-loading.tsx")],
    {
      encoding: "utf8",
      timeout: 10_000,
    },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
