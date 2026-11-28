import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const runtimePaths = [
  "src",
  "package.json",
  "bun.lock",
  "bunfig.toml",
  "tsconfig.json",
];

export function runtimeFingerprint(root: string, revision: string): string {
  const objects = execFileSync(
    "git",
    ["rev-parse", ...runtimePaths.map((path) => `${revision}:${path}`)],
    { cwd: root, encoding: "utf8" },
  );
  return createHash("sha256").update(objects).digest("hex");
}

export function assertCleanRuntime(root: string): void {
  const changes = execFileSync(
    "git",
    ["status", "--porcelain", "--untracked-files=all", "--", ...runtimePaths],
    { cwd: root, encoding: "utf8" },
  );
  if (changes.trim())
    throw new Error("Commit runtime changes before evaluating");
}
