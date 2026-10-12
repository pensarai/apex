import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "issues.ts");

// Cases run through this exit before any API call, so they stay offline.
function runIssues(args: string[]) {
  const result = spawnSync("bun", [CLI, ...args], { encoding: "utf8" });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

// Runs the CLI against a local stand-in for the Console API and returns the one request it sent.
async function captureRequest(args: string[]) {
  let request:
    | { method?: string; url?: string; body: Record<string, unknown> }
    | undefined;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      request = {
        method: req.method,
        url: req.url,
        body: JSON.parse(Buffer.concat(chunks).toString("utf-8")),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, issue: {} }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("no port");
  }
  const home = mkdtempSync(join(tmpdir(), "pensar-issues-"));
  try {
    const status = await new Promise<number | null>((resolve) => {
      const child = spawn("bun", [CLI, ...args], {
        env: {
          ...process.env,
          HOME: home,
          PENSAR_API_KEY: "test-key",
          PENSAR_API_URL: `http://127.0.0.1:${address.port}`,
        },
        stdio: "ignore",
      });
      child.on("exit", resolve);
    });
    expect(status).toBe(0);
  } finally {
    server.close();
    rmSync(home, { recursive: true, force: true });
  }
  if (!request) throw new Error("CLI sent no request");
  return request;
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
    expect(stdout).toContain("resolved, duplicate, wont-fix");
    expect(stdout).toContain("--duplicate-of <issueId>");
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
    expect(stderr).toContain(
      "resolved, duplicate, wont-fix, out-of-scope, risk-accepted",
    );
  });

  it("requires --duplicate-of to close as a duplicate", () => {
    const { status, stderr } = runIssues([
      "update",
      "VULN-000001",
      "--status",
      "closed",
      "--disposition",
      "duplicate",
    ]);

    expect(status).toBe(1);
    expect(stderr).toContain(
      "--disposition duplicate requires --duplicate-of <issueId>",
    );
  });

  it.each([
    [["--status", "closed", "--duplicate-of", "VULN-000002"]],
    [
      [
        "--status",
        "closed",
        "--disposition",
        "resolved",
        "--duplicate-of",
        "VULN-000002",
      ],
    ],
  ])("rejects --duplicate-of without the duplicate disposition (%j)", (flags) => {
    const { status, stderr } = runIssues(["update", "VULN-000001", ...flags]);

    expect(status).toBe(1);
    expect(stderr).toContain("--duplicate-of requires --disposition duplicate");
  });

  it("sends the original as duplicateOf on a duplicate close", async () => {
    const request = await captureRequest([
      "update",
      "VULN-000001",
      "--status",
      "closed",
      "--disposition",
      "duplicate",
      "--duplicate-of",
      "VULN-000002",
    ]);

    expect(request.method).toBe("PATCH");
    expect(request.url).toBe("/issues/VULN-000001");
    expect(request.body).toEqual({
      status: "closed",
      closedDisposition: "duplicate",
      duplicateOf: "VULN-000002",
    });
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
