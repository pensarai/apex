import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";

it("rejects conflicting v2 workflows before making a model call", () => {
  for (const flag of ["--lance", "--fast-strike", "--task-driven"]) {
    const result = spawnSync(
      "bun",
      [
        "--no-env-file",
        join(import.meta.dirname, "../cli.ts"),
        "--default-v2",
        "--prompt",
        "fixture",
        flag,
      ],
      { encoding: "utf8", timeout: 30_000 },
    );
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Default v2 cannot be combined");
  }
});
