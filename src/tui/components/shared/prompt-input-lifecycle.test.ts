import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it.each([
  "clear-input",
  "history-live",
  "ctrl-c-after-exit",
  "history-after-exit",
])("handles native prompt lifecycle: %s", (scenario) => {
  // OpenTUI's native buffer bindings run in Bun, not Vitest's Node process.
  const result = spawnSync(
    "bun",
    [
      join(import.meta.dirname, "__tests__/prompt-input-lifecycle.tsx"),
      scenario,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
