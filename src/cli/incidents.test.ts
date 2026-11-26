import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "incidents.ts");
const ID = "11111111-1111-4111-8111-111111111111";

async function request(args: string[], response: unknown, statusCode = 200) {
  let url = "";
  let method = "";
  const server = createServer((req, res) => {
    url = req.url ?? "";
    method = req.method ?? "";
    res.writeHead(statusCode, { "Content-Type": "application/json" });
    res.end(JSON.stringify(response));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Missing test server port");
  const taskHome = mkdtempSync(join(tmpdir(), "pensar-incidents-"));
  let stdout = "";
  let stderr = "";
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      const child = spawn("bun", [CLI, ...args], {
        env: {
          ...process.env,
          HOME: taskHome,
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
    return { url, method, stdout, stderr, code };
  } finally {
    server.close();
    rmSync(taskHome, { recursive: true, force: true });
  }
}

describe("pensar incidents", () => {
  it.each(
    [[], ["get"], ["events"], ["logs"], ["attachment"]].map((args) => ({
      args,
    })),
  )("shows help before requesting authentication", ({ args }) => {
    const result = spawnSync("bun", [CLI, ...args, "--help"], {
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("incidents:read");
  });

  it.each(
    [
      ["get"],
      ["logs"],
      ["attachment", ID],
      ["unknown"],
      ["--limit", "NaN"],
      ["logs", ID, "--limit", "51"],
      ["--status", "unknown"],
      ["get", ID, "--cursor", "x"],
      ["--group-of", ID],
    ].map((args) => ({ args })),
  )("rejects invalid arguments before an API call", ({ args }) => {
    const result = spawnSync("bun", [CLI, ...args], { encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(result.stderr).not.toContain("Not authenticated");
  });

  it("defaults to all-verdict grouped alerts and preserves the next cursor", async () => {
    const response = {
      incidents: [{ id: ID, verdict: "benign-true-positive" }],
      nextCursor: "next",
    };
    const result = await request(["--json"], response);
    expect(result).toMatchObject({ code: 0, method: "GET", url: "/incidents" });
    expect(JSON.parse(result.stdout)).toEqual(response);
  });

  it("encodes event filters and an opaque cursor", async () => {
    const result = await request(
      [
        "events",
        "--group-of",
        ID,
        "--verdict",
        "false-positive",
        "--triage-status",
        "completed",
        "--limit",
        "7",
        "--cursor",
        "a+/= b",
      ],
      { events: [], nextCursor: null },
    );
    const url = new URL(result.url, "https://api.example.com");
    expect(url.pathname).toBe("/incidents/events");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      groupOf: ID,
      verdict: "false-positive",
      triageStatus: "completed",
      limit: "7",
      cursor: "a+/= b",
    });
  });

  it("does not trim raw payloads or remediation commands", async () => {
    const response = {
      id: ID,
      rawPayload: { message: "x".repeat(9_000) },
      triageResult: {
        remediation: [{ action: "Code change required: add caching" }],
        verdict: "benign-true-positive",
      },
    };
    const result = await request(["get", ID, "--json"], response);
    expect(result.url).toBe(`/incidents/${ID}`);
    expect(JSON.parse(result.stdout)).toEqual(response);
  });

  it("reads log pages and fetches the full-output download URL separately", async () => {
    const result = await request(
      ["logs", ID, "--limit", "1", "--cursor", "next"],
      { parts: [{ id: "part_1", hasAttachment: true }], nextCursor: null },
    );
    expect(result.url).toBe(`/incidents/${ID}/logs?limit=1&cursor=next`);
    const attachment = {
      downloadUrl: "https://storage.example.com/log",
      expiresIn: 60,
    };
    const downloaded = await request(["attachment", ID, "part_1"], attachment);
    expect(downloaded.url).toBe(`/incidents/${ID}/logs/part_1/attachment`);
    expect(JSON.parse(downloaded.stdout)).toEqual(attachment);
  });

  it("surfaces authorization errors and exits unsuccessfully", async () => {
    const result = await request(
      ["get", ID],
      { error: "Missing incidents:read" },
      403,
    );
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("Missing incidents:read");
    expect(result.stdout).toBe("");
  });
});
