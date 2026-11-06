import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it("discovers Ollama after launch, selects a model, and preserves the selection after disconnect", () => {
  const result = spawnSync(
    "bun",
    [join(import.meta.dirname, "__tests__/ollama-discovery.tsx")],
    { encoding: "utf8", timeout: 30_000 },
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});
