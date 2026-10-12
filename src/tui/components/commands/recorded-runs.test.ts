import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it.each([
  "direct-run-offline",
  "list-attach-detach",
  "approval-and-control-binding",
  "approval-acks-before-watch-refresh",
  "busy-controls-consume-shortcuts",
  "sticky-worker-error",
  "late-open-detach",
  "scroll-transcript",
  "spec-start-once",
  "spec-start-back-to-list",
  "spec-start-viewing-other-run",
  "list-refresh-keeps-selection",
  "list-refresh-preserves-pending-move",
  "list-refresh-replaces-vanished-selection",
  "resume-uncertain",
  "resume-rejected",
  "spec-start-uncertain",
  "sequential-controls-before-watch-refresh",
  "control-ack-keeps-newer-watch",
  "control-stale-watch-keeps-ack",
  "blockers-survive-actions-after-retirement",
  "control-new-attempt-watch-beats-old-ack",
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
