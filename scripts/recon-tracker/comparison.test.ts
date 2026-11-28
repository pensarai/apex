import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, it } from "vitest";
import { assertCleanRuntime, runtimeFingerprint } from "./revision";
import { loadScope } from "./scope";

const roots: string[] = [];
function temporary() {
  const root = mkdtempSync(join(tmpdir(), "recon-compare-"));
  roots.push(root);
  return root;
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function fixture(arm = "baseline", fingerprint?: string) {
  const root = temporary();
  const save = (name: string, data: unknown) =>
    writeFileSync(join(root, name), JSON.stringify(data));
  save("inputs.json", {
    arm,
    commit: "unavailable-archived-commit",
    runtimeFingerprint: fingerprint,
  });
  save("scope.json", loadScope("app.example"));
  save("result.json", {
    status: "completed",
    elapsedSeconds: 1,
    estimatedUsd: null,
  });
  save("topology.json", {
    components: [],
    boundaries: [],
    flows: [],
    controls: [],
    retired: [],
    threats: [
      {
        id: "thr_orphan",
        componentId: "cmp_retired",
        title: "Surviving threat",
      },
    ],
  });
  writeFileSync(join(root, "coverage.csv"), "broken,header\n");
  writeFileSync(
    join(root, "events.jsonl"),
    ["app.example", "https://app.example/"]
      .flatMap((url, i) => [
        {
          event: "tool-call-complete",
          data: {
            toolName: "http_request",
            toolCallId: String(i),
            args: { url },
          },
        },
        {
          event: "tool-result",
          data: {
            toolName: "http_request",
            toolCallId: String(i),
            result: { status: i ? 200 : 0 },
          },
        },
      ])
      .map((event) => JSON.stringify(event))
      .join("\n"),
  );
  return root;
}
const compare = (...args: string[]) =>
  spawnSync("bun", [resolve("scripts/compare-recon-tracker.ts"), ...args], {
    encoding: "utf8",
  });

it("reviews archived outputs despite invalid URLs and a malformed ledger", () => {
  const root = fixture();
  const result = compare("--baseline", root);
  expect(result.status, result.stderr).toBe(0);
  const [run] = JSON.parse(result.stdout);
  expect(run.coverage.structuredHttpAttemptDomains).toBe(1);
  expect(run.coverage.trackerPending).toBeNull();
  expect(readFileSync(join(root, "review.html"), "utf8")).toContain(
    "Surviving threat",
  );
});

it("rejects mismatched arms and dependency fingerprints", () => {
  const baseline = fixture("baseline", "same");
  expect(
    compare("--baseline", baseline, "--tracker", baseline).stderr,
  ).toContain("Expected tracker");
  const tracker = fixture("tracker", "different");
  expect(
    compare("--baseline", baseline, "--tracker", tracker).stderr,
  ).toContain("Unmatched comparison: runtimeFingerprint");
});

it("matches documentation changes but rejects dirty or changed runtime inputs", () => {
  const root = temporary();
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: root, stdio: "pipe" });
  git("init");
  git("config", "user.name", "Eval test");
  git("config", "user.email", "eval@example.test");
  mkdirSync(join(root, "src"));
  for (const name of [
    "src/index.ts",
    "package.json",
    "bun.lock",
    "bunfig.toml",
    "tsconfig.json",
    "README.md",
  ])
    writeFileSync(join(root, name), "initial");
  git("add", ".");
  git("commit", "-m", "initial");
  const original = runtimeFingerprint(root, "HEAD");
  writeFileSync(join(root, "README.md"), "docs");
  expect(() => assertCleanRuntime(root)).not.toThrow();
  git("add", ".");
  git("commit", "-m", "docs");
  expect(runtimeFingerprint(root, "HEAD")).toBe(original);
  writeFileSync(join(root, "bun.lock"), "upgrade");
  expect(() => assertCleanRuntime(root)).toThrow("Commit runtime changes");
  git("add", ".");
  git("commit", "-m", "dependency");
  expect(runtimeFingerprint(root, "HEAD")).not.toBe(original);
  writeFileSync(join(root, "src/new.ts"), "untracked");
  expect(() => assertCleanRuntime(root)).toThrow("Commit runtime changes");
});
