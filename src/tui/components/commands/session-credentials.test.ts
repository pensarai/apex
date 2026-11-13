import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it("adds a credential from the operator dialog without rendering its secrets", () => {
  const result = spawnSync(
    "bun",
    [join(import.meta.dirname, "__tests__/session-credentials-lifecycle.tsx")],
    {
      encoding: "utf8",
      timeout: 30_000,
    },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
