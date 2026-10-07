import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it.each([
  "direct-run-offline",
  "list-attach-detach",
  "approval-and-control-binding",
  "sticky-worker-error",
  "late-open-detach",
  "scroll-transcript",
  "spec-start-once",
  "spec-start-back-to-list",
  "spec-start-viewing-other-run",
  "list-refresh-keeps-selection",
  "list-refresh-preserves-pending-move",
  "list-refresh-replaces-vanished-selection",
])("recorded-runs dialog lifecycle: %s", (scenario) => {
  // OpenTUI's native buffer bindings and bun:test mock.module run in Bun.
  const result = spawnSync(
    "bun",
    [
      join(import.meta.dirname, "__tests__/recorded-runs-lifecycle.tsx"),
      scenario,
    ],
    { encoding: "utf8", timeout: 20_000 },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
