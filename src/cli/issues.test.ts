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
    "comments",
    "comment",
  ])("prints help for `%s --help` instead of treating it as an issue id", (sub) => {
    const { status, stdout, stderr } = runIssues([sub, "--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain("pensar issues — Manage security issues");
    expect(stderr).toBe("");
  });

  it("documents the close disposition on update", () => {
    const { status, stdout } = runIssues(["--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain("--disposition <value>");
    expect(stdout).toContain("resolved, wont-fix, out-of-scope");
  });

  it("rejects a disposition outside the accepted set, naming the set", () => {
    const { status, stderr } = runIssues([
      "update",
      "VULN-000001",
      "--disposition",
      "other",
    ]);

    expect(status).toBe(1);
    expect(stderr).toContain('invalid --disposition "other"');
    expect(stderr).toContain("resolved, wont-fix, out-of-scope, risk-accepted");
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

  it("requires an issue ID to read a thread", () => {
    const { status, stderr } = runIssues(["comments"]);

    expect(status).toBe(1);
    expect(stderr).toContain("Usage: pensar issues comments <issueId>");
  });

  // Without this the flag is swallowed as the issue id and the request goes
  // out with an empty comment.
  it("requires --body to post a comment", () => {
    const { status, stderr } = runIssues(["comment", "VULN-000123"]);

    expect(status).toBe(1);
    expect(stderr).toContain("issue ID and --body are required");
  });

  it("does not mistake a flag for the issue id when posting", () => {
    const { status, stderr } = runIssues(["comment", "--body", "hi"]);

    expect(status).toBe(1);
    expect(stderr).toContain("issue ID and --body are required");
  });

  it("says posting needs a user login, not just an API key", () => {
    const { status, stdout } = runIssues(["--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain("Posting requires a user login");
  });
});
