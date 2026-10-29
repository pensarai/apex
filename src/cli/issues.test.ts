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
async function captureRequest(
  args: string[],
  response: unknown = { success: true, issue: {} },
  statusCode = 200,
) {
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
        body: JSON.parse(Buffer.concat(chunks).toString("utf-8") || "{}"),
      };
      res.writeHead(statusCode, { "Content-Type": "application/json" });
      res.end(JSON.stringify(response));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("no port");
  }
  const home = mkdtempSync(join(tmpdir(), "pensar-issues-"));
  let stdout = "";
  let stderr = "";
  let status: number | null;
  try {
    status = await new Promise<number | null>((resolve, reject) => {
      const child = spawn("bun", [CLI, ...args], {
        env: {
          ...process.env,
          HOME: home,
          PENSAR_API_KEY: "test-key",
          PENSAR_API_URL: `http://127.0.0.1:${address.port}`,
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });
      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });
      child.on("error", reject);
      child.on("close", resolve);
    });
    expect(status).toBe(statusCode < 400 ? 0 : 1);
  } finally {
    server.close();
    rmSync(home, { recursive: true, force: true });
  }
  if (!request) throw new Error("CLI sent no request");
  return { ...request, stdout, stderr, status };
}

describe("pensar issues CLI", () => {
  it("documents the label and Console url on issue details", () => {
    const { status, stdout } = runIssues(["--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain('Issue details include "label"');
    expect(stdout).toContain("issue in the Console");
  });

  it.each([
    "get",
    "evidence",
    "retests",
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

  it.each([
    "VULN-000123",
    "11111111-1111-4111-8111-111111111111",
  ])("launches a retest for %s through the existing API", async (issueId) => {
    const request = await captureRequest(["retest", issueId]);
    expect(request.method).toBe("POST");
    expect(request.url).toBe(`/issues/${issueId}/retest`);
    expect(request.body).toEqual({});
  });

  it("requires an issue ID to launch a retest", () => {
    const { status, stderr } = runIssues(["retest"]);
    expect(status).toBe(1);
    expect(stderr).toContain("Usage: pensar issues retest <issueId>");
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

describe("finding reads", () => {
  const issueId = "VULN-000123";
  const evidence = {
    issueId,
    poc: { fileName: "poc.py", language: "python", contents: "print('proof')" },
    pocOutput: {
      stdout: "[REDACTED]\nproof",
      stderr: "",
      exitCode: 0,
      executedAt: "2026-10-28T00:00:00.000Z",
      truncated: true,
    },
    steps: [
      {
        title: "Authenticate",
        description: "Use [REDACTED]",
        artifactIds: ["proof"],
      },
    ],
    attackPath: [
      {
        application: { id: "app-id", name: "Acme API" },
        host: "app.acme.example",
        relationship: "entry",
        notes: "Public route",
      },
    ],
    codeSnippet: null,
    codeSnippetReason: "no_repository",
    futureEvidence: { preserved: true },
  };

  it.each([
    [
      "get",
      "",
      {
        id: issueId,
        label: issueId,
        title: "Reflected XSS",
        cwe: ["CWE-79"],
        location: null,
        startLine: null,
        endLine: null,
        application: { id: "app-id", name: "Acme API" },
        endpoint: null,
        cvss: {
          score: 0,
          vector: "CVSS:4.0/AV:N",
          metrics: { AV: "N" },
          severityOverride: {
            severity: "low",
            reason: "Reviewed",
            setBy: "reviewer",
            setAt: "2026-10-28T00:00:00.000Z",
          },
        },
        repository: null,
        futureField: { preserved: true },
      },
    ],
    ["evidence", "/evidence", evidence],
    [
      "retests",
      "/retests",
      [
        {
          id: "retest-id",
          status: "fixed",
          stillExists: false,
          confidence: "high",
          evidence: "No longer reproduced",
          recommendation: "Close",
          error: null,
        },
      ],
    ],
  ])("passes the complete %s JSON through unchanged", async (command, suffix, response) => {
    const result = await captureRequest(
      [command as string, issueId, "--json"],
      response,
    );
    expect(result.method).toBe("GET");
    expect(result.url).toBe(`/issues/${issueId}${suffix}`);
    expect(JSON.parse(result.stdout)).toEqual(response);
    expect(result.stderr).toBe("");
  });

  it("renders nested evidence, redactions and truncation without losing values", async () => {
    const { stdout } = await captureRequest(["evidence", issueId], evidence);
    expect(stdout).toContain("Poc output:");
    expect(stdout).toContain("Stdout: [REDACTED]\n  proof");
    expect(stdout).toContain("Exit code: 0");
    expect(stdout).toContain("Truncated: true");
    expect(stdout).toContain("Title: Authenticate");
    expect(stdout).toContain("Name: Acme API");
    expect(stdout).toContain("Code snippet: None");
    expect(stdout).toContain("Code snippet reason: no_repository");
    expect(stdout).toContain("Future evidence:");
  });

  it("renders issue fields and false booleans in the default output", async () => {
    const response = {
      title: "SQL injection",
      cvss: { score: 9.1, severityOverride: { reason: "Reviewed" } },
      closedAt: null,
      confirmed: false,
    };
    const { stdout } = await captureRequest(["get", issueId], response);
    expect(stdout).toContain("Title: SQL injection");
    expect(stdout).toContain("Score: 9.1");
    expect(stdout).toContain("Reason: Reviewed");
    expect(stdout).toContain("Closed at: None");
    expect(stdout).toContain("Confirmed: false");
  });

  it("renders a code snippet at its recorded commit", async () => {
    const response = {
      ...evidence,
      codeSnippet: {
        repositoryId: "repo-id",
        path: "src/db/query.ts",
        startLine: 140,
        endLine: 146,
        commit: "abc123",
        content: "query(input);",
        truncated: false,
      },
      codeSnippetReason: null,
    };
    const { stdout } = await captureRequest(["evidence", issueId], response);
    expect(stdout).toContain("Commit: abc123");
    expect(stdout).toContain("Path: src/db/query.ts");
    expect(stdout).toContain("Start line: 140");
    expect(stdout).toContain("End line: 146");
    expect(stdout).toContain("Content: query(input);");
    expect(stdout).toContain("Truncated: false");
  });

  it("preserves absent evidence as null in JSON output", async () => {
    const response = {
      issueId,
      poc: null,
      pocOutput: null,
      steps: null,
      artifacts: null,
      evidenceStatus: null,
      attackPath: null,
      codeSnippet: null,
      codeSnippetReason: "no_repository",
    };
    const { stdout } = await captureRequest(
      ["evidence", issueId, "--json"],
      response,
    );
    expect(JSON.parse(stdout)).toEqual(response);
  });

  it("renders an empty retest history", async () => {
    const { stdout } = await captureRequest(["retests", issueId], []);
    expect(stdout.trim()).toBe("None");
  });

  it.each([
    "get",
    "evidence",
    "retests",
  ])("rejects missing IDs and flags as IDs for %s", (command) => {
    for (const args of [[command], [command, "--json"]]) {
      const result = runIssues(args);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        `Usage: pensar issues ${command} <issueId> [--json]`,
      );
    }
  });

  it.each([
    403, 404,
  ])("surfaces an API %s without printing a partial result", async (status) => {
    const { stdout, stderr } = await captureRequest(
      ["evidence", issueId, "--json"],
      { error: "Issue unavailable" },
      status,
    );
    expect(stdout).toBe("");
    expect(stderr).toContain(`API error (${status}): Issue unavailable`);
  });
});
