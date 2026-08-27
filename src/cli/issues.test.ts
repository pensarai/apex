import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "issues.ts");

// Every case below prints help and exits before any API call, so these stay offline.
function runIssues(args: string[]) {
  const result = spawnSync("bun", [CLI, ...args], { encoding: "utf8" });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

describe("pensar issues CLI", () => {
  it("documents issueLabel and the Console url on issue responses", () => {
    const { status, stdout } = runIssues(["--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain("issueLabel");
    expect(stdout).toContain("deep link to the issue in the Console");
  });

  it.each([
    "get",
    "update",
    "retest",
    "link-pr",
    "prs",
  ])("prints help for `%s --help` instead of treating it as an issue id", (sub) => {
    const { status, stdout, stderr } = runIssues([sub, "--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain("pensar issues — Manage security issues");
    expect(stderr).toBe("");
  });

  it("prints help for `-h` on a subcommand", () => {
    const { status, stdout } = runIssues(["update", "-h"]);

    expect(status).toBe(0);
    expect(stdout).toContain("pensar issues — Manage security issues");
  });

  it("still requires an issue ID when help was not requested", () => {
    const { status, stderr } = runIssues(["get"]);

    expect(status).toBe(1);
    expect(stderr).toContain("Usage: pensar issues get <issueId>");
  });
});
