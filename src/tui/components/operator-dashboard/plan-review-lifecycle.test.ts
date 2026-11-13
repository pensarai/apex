import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it.each([
  "snapshot-changed",
  "snapshot-deleted",
  "snapshot-rejected",
  "snapshot-refined",
  "queue-normal",
  "queue-review-running",
  "queue-refine-running",
  "queue-refine-waiting",
  "queue-stale-submission",
  "queue-approve-running",
  "queue-approve",
  "queue-reject",
  "queue-refine",
])("preserves the plan review boundary: %s", (scenario) => {
  const result = spawnSync(
    "bun",
    [
      join(import.meta.dirname, "__tests__/plan-review-lifecycle.tsx"),
      scenario,
    ],
    { encoding: "utf8", timeout: 15_000 },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
