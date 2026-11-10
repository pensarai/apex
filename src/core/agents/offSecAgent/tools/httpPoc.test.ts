import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DestructiveActionError } from "./destructiveGuard";
import {
  buildHttpPocScript,
  HttpPocError,
  type HttpPocRequest,
} from "./httpPoc";
import { ScopeViolationError } from "./scopeGuard";
import type { ToolContext } from "./types";

function makeCtx(target: string): ToolContext {
  return {
    target,
    session: { targets: [target], config: {} },
  } as unknown as ToolContext;
}

const ssrf: HttpPocRequest = {
  method: "POST",
  url: "https://app.acme.example/hooks",
  headers: { "Content-Type": "application/json" },
  body: '{"url": "http://169.254.169.254/latest/meta-data/"}',
  expectStatus: 200,
};

describe("buildHttpPocScript checks", () => {
  const ctx = makeCtx("https://app.acme.example");

  it("allows internal URLs sent as data to an in-scope target", () => {
    expect(() => buildHttpPocScript([ssrf], ctx)).not.toThrow();
    expect(() =>
      buildHttpPocScript(
        [
          {
            method: "GET",
            url: "https://app.acme.example/fetch?a=1&url=http://[::1]/admin",
            headers: { Referer: "http://localhost:8080/" },
            expectStatus: 200,
          },
        ],
        ctx,
      ),
    ).not.toThrow();
  });

  it("rejects a request to a host outside scope", () => {
    expect(() =>
      buildHttpPocScript(
        [ssrf, { method: "GET", url: "http://169.254.169.254/latest/" }],
        ctx,
      ),
    ).toThrow(ScopeViolationError);
  });

  it("checks the host curl will request, not the raw text", () => {
    // Parsed as a URL, the backslash ends the host, so the scope check and
    // curl both see app.acme.example and the rest is path.
    const script = buildHttpPocScript(
      [
        {
          method: "GET",
          url: "https://app.acme.example\\@evil.example/",
          expectStatus: 200,
        },
      ],
      ctx,
    );
    expect(script).toContain("--url 'https://app.acme.example/@evil.example/'");
    expect(() =>
      buildHttpPocScript(
        [
          {
            method: "GET",
            url: "https://app.acme.example@evil.example/",
            expectStatus: 200,
          },
        ],
        ctx,
      ),
    ).toThrow(ScopeViolationError);
  });

  it("applies the destructive-action block", () => {
    expect(() =>
      buildHttpPocScript(
        [
          {
            method: "POST",
            url: "https://app.acme.example/api/v2/payout-links",
            headers: { "Content-Type": "application/json" },
            body: '{"amount":99999999,"funding_source":"ach"}',
            expectStatus: 200,
          },
        ],
        ctx,
      ),
    ).toThrow(DestructiveActionError);
  });

  it.each<[string, HttpPocRequest[]]>([
    ["no requests", []],
    ["no expectation", [{ method: "GET", url: "https://app.acme.example/" }]],
    [
      "a non-HTTP scheme",
      [{ method: "GET", url: "file:///etc/passwd", expectStatus: 200 }],
    ],
    [
      "a bad method",
      [
        {
          method: "GET /x",
          url: "https://app.acme.example/",
          expectStatus: 200,
        },
      ],
    ],
    [
      "a header line break",
      [
        {
          method: "GET",
          url: "https://app.acme.example/",
          headers: { "X-A": "1\r\nHost: evil.example" },
          expectStatus: 200,
        },
      ],
    ],
    [
      "a bad header name",
      [
        {
          method: "GET",
          url: "https://app.acme.example/",
          headers: { "X A": "1" },
          expectStatus: 200,
        },
      ],
    ],
    [
      // grep would pass if any one line matched.
      "a multi-line expected text",
      [
        {
          method: "GET",
          url: "https://app.acme.example/",
          expectBodyContains: "admin\nsecret",
        },
      ],
    ],
  ])("rejects %s", (_, requests) => {
    expect(() => buildHttpPocScript(requests, ctx)).toThrow(HttpPocError);
  });
});

describe.skipIf(process.platform === "win32")(
  "buildHttpPocScript scripts",
  () => {
    let server: Server;
    let origin: string;
    const received: Array<{ method?: string; headers: object; body: string }> =
      [];

    beforeAll(async () => {
      server = createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => {
          received.push({ method: req.method, headers: req.headers, body });
          if (req.url?.startsWith("/redirect")) {
            // Same server, so a followed redirect would show up in `received`.
            res.writeHead(302, { Location: "/landed" });
            res.end();
            return;
          }
          res.writeHead(req.url === "/missing" ? 404 : 200);
          res.end(`echo: ${body}`);
        });
      });
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", resolve),
      );
      origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    afterAll(() => {
      server.close();
    });

    // Async, so the in-process server can answer while the script runs.
    function run(
      requests: HttpPocRequest[],
    ): Promise<{ status: number | null; stdout: string }> {
      received.length = 0;
      const script = buildHttpPocScript(requests, makeCtx(origin));
      return new Promise((resolve) => {
        execFile("bash", ["-c", script], (error, stdout) => {
          resolve({ status: error ? (error.code as number) : 0, stdout });
        });
      });
    }

    it("sends method, headers and body exactly, and exits 0 when expectations hold", async () => {
      const body = `{"url": "http://169.254.169.254/", "q": "it's @here $(id) \`id\`"}`;
      const result = await run([
        {
          method: "post",
          url: `${origin}/hooks`,
          headers: { "Content-Type": "application/json", "X-Note": "a'b" },
          body,
          expectStatus: 200,
          expectBodyContains: "169.254.169.254",
        },
      ]);

      expect(result.status).toBe(0);
      expect(received).toHaveLength(1);
      expect(received[0].method).toBe("POST");
      expect(received[0].body).toBe(body);
      expect(received[0].headers).toMatchObject({
        "content-type": "application/json",
        "x-note": "a'b",
      });
      expect(result.stdout).toContain("status: 200");
    });

    it("does not follow a redirect, so an open-redirect payload is never requested", async () => {
      const result = await run([
        {
          method: "GET",
          url: `${origin}/redirect?next=http://evil.example/`,
          expectStatus: 302,
        },
      ]);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("status: 302");
      expect(received).toHaveLength(1);
    });

    it("sends a body that starts with @ instead of reading a file", async () => {
      const result = await run([
        {
          method: "POST",
          url: `${origin}/hooks`,
          body: "@/etc/passwd",
          expectStatus: 200,
        },
      ]);
      expect(result.status).toBe(0);
      expect(received[0].body).toBe("@/etc/passwd");
    });

    it("exits non-zero when a status or body expectation fails", async () => {
      expect(
        (
          await run([
            { method: "GET", url: `${origin}/missing`, expectStatus: 200 },
          ])
        ).status,
      ).toBe(1);
      const result = await run([
        {
          method: "GET",
          url: `${origin}/`,
          expectBodyContains: "ami-id",
        },
      ]);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain(
        "FAIL: response does not contain the expected text",
      );
    });

    it("runs requests in order and fails if any expectation fails", async () => {
      const result = await run([
        { method: "GET", url: `${origin}/login` },
        { method: "GET", url: `${origin}/missing`, expectStatus: 200 },
        { method: "GET", url: `${origin}/after`, expectStatus: 200 },
      ]);
      expect(result.status).toBe(1);
      expect(received).toHaveLength(3);
    });
  },
);
