import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it("renders tool lifecycle updates without arguments in the native TUI", () => {
  const result = spawnSync(
    "bun",
    [join(import.meta.dirname, "__tests__/tool-renderer-lifecycle.tsx")],
    { encoding: "utf8", timeout: 10_000 },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
