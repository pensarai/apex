import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "knowledge.ts");
const ID = "33333333-3333-4333-8333-333333333333";

function run(args: string[]) {
  const result = spawnSync("bun", [CLI, ...args], { encoding: "utf8" });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

async function captureRequest(args: string[]) {
  let request: { method?: string; url?: string; body: unknown } | undefined;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf-8");
      request = {
        method: req.method,
        url: req.url,
        body: raw ? JSON.parse(raw) : undefined,
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: ID }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("no port");
  const home = mkdtempSync(join(tmpdir(), "pensar-knowledge-"));
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

describe("pensar knowledge CLI", () => {
  it("documents that writes need a user login", () => {
    const { status, stdout } = run(["--help"]);
    expect(status).toBe(0);
    expect(stdout).toContain("require a user login");
  });

  it("lists with filters", async () => {
    const req = await captureRequest([
      "--category",
      "user_note",
      "--status",
      "active",
      "--tag",
      "auth,api",
    ]);
    expect(req.method).toBe("GET");
    expect(req.url).toBe(
      "/knowledge?category=user_note&status=active&tags=auth%2Capi",
    );
  });

  it("adds an entry", async () => {
    const req = await captureRequest([
      "add",
      "--title",
      "Stack",
      "--content",
      "Next.js on Lambda",
      "--category",
      "technology_context",
      "--tag",
      "infra",
    ]);
    expect(req).toMatchObject({
      method: "POST",
      url: "/knowledge",
      body: {
        title: "Stack",
        content: "Next.js on Lambda",
        category: "technology_context",
        tags: ["infra"],
      },
    });
  });

  it("updates an entry", async () => {
    const req = await captureRequest(["update", ID, "--status", "stale"]);
    expect(req).toMatchObject({
      method: "PATCH",
      url: `/knowledge/${ID}`,
      body: { status: "stale" },
    });
  });

  it("archives an entry", async () => {
    const req = await captureRequest(["archive", ID]);
    expect(req).toMatchObject({ method: "DELETE", url: `/knowledge/${ID}` });
  });

  it("requires title, content and category to add", () => {
    const { status, stderr } = run(["add", "--title", "x"]);
    expect(status).toBe(1);
    expect(stderr).toContain("--title, --content and --category are required");
  });

  it("rejects an unknown category before calling the API", () => {
    const { status, stderr } = run(["add", "--category", "nope"]);
    expect(status).toBe(1);
    expect(stderr).toContain('invalid --category "nope"');
  });

  it("requires an id for get", () => {
    const { status, stderr } = run(["get"]);
    expect(status).toBe(1);
    expect(stderr).toContain("entry ID is required");
  });
});
