import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { crawlAuthenticated } from "./crawlAuthenticated";
import type { ToolContext } from "./types";

function makeCtx(sessionOverrides: Partial<SessionInfo> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
      ...sessionOverrides,
    } as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
  };
}

interface RecordedRequest {
  url: string;
  headers: Record<string, string>;
}

function headerValue(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  const match = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === name,
  );
  return match ? String(match[1]) : undefined;
}

type ServePage = (
  url: string,
  headers: Record<string, string>,
) => { status: number; body: string };

function stubFetch(serve: ServePage): RecordedRequest[] {
  const requests: RecordedRequest[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      requests.push({ url: String(url), headers });
      const served = serve(String(url), headers);
      return new Response(served.body, { status: served.status });
    }),
  );
  return requests;
}

function servePages(pages: Record<string, string>): ServePage {
  return (url) =>
    url in pages
      ? { status: 200, body: pages[url] }
      : { status: 404, body: "" };
}

const DASHBOARD_HTML = `<html><body>
<a href="/settings">Settings</a>
<a href="https://external.example.com/other">Out of scope link</a>
<form action="/login"><input name="u"></form>
<script>fetch('/api/stats'); url = "/api/stats"; fetch('/api/notes');</script>
</body></html>`;

const SETTINGS_HTML = `<html><body>
<a href="/settings">Reload</a>
<script>fetch('/api/settings/save');</script>
</body></html>`;

const CRAWL_INPUT = {
  startUrl: "https://example.com/dashboard",
  sessionCookie: "sid=abc",
  maxDepth: 2,
  maxPages: 10,
  toolCallDescription: "Crawl fixture site",
};

interface CrawlResult {
  success: boolean;
  message: string;
  startUrl?: string;
  pagesVisited?: number;
  totalPages?: number;
  pages?: Array<{
    url: string;
    status: number;
    links: string[];
    forms: string[];
    jsEndpoints: Array<{ endpoint: string; pattern: string; source: string }>;
  }>;
  allDiscoveredEndpoints?: string[];
}

function execute(input: typeof CRAWL_INPUT) {
  return crawlAuthenticated(makeCtx()).execute?.(input, {
    toolCallId: "tc_test",
    messages: [],
    abortSignal: undefined,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("crawlAuthenticated", () => {
  it("issues exactly one authenticated request per visited page", async () => {
    const requests = stubFetch(
      servePages({
        "https://example.com/dashboard": DASHBOARD_HTML,
        "https://example.com/settings": SETTINGS_HTML,
      }),
    );

    const result = (await execute(CRAWL_INPUT)) as CrawlResult;

    expect(result.success).toBe(true);
    expect(result.pagesVisited).toBe(2);
    // The crawler must reuse its own authenticated download for JS endpoint
    // extraction instead of fetching every page a second time. Relative links
    // are resolved to absolute URLs before the request.
    expect(requests.map((r) => r.url).sort()).toEqual([
      "https://example.com/dashboard",
      "https://example.com/settings",
    ]);
    for (const request of requests) {
      expect(headerValue(request.headers, "cookie")).toBe("sid=abc");
    }
  });

  it("returns the full crawl map with deduplicated JS endpoints per page", async () => {
    const requests = stubFetch(
      servePages({
        "https://example.com/dashboard": DASHBOARD_HTML,
        "https://example.com/settings": SETTINGS_HTML,
      }),
    );

    const result = (await execute(CRAWL_INPUT)) as CrawlResult;

    expect(result).toEqual({
      success: true,
      startUrl: "https://example.com/dashboard",
      pagesVisited: 2,
      totalPages: 2,
      pages: [
        {
          url: "https://example.com/dashboard",
          status: 200,
          links: ["/settings"],
          forms: ["/login"],
          jsEndpoints: [
            {
              endpoint: "/api/stats",
              pattern: "fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]...",
              source: "inline-script",
            },
            {
              endpoint: "/api/notes",
              pattern: "fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]...",
              source: "inline-script",
            },
          ],
        },
        {
          url: "https://example.com/settings",
          status: 200,
          links: ["/settings"],
          forms: [],
          jsEndpoints: [
            {
              endpoint: "/api/settings/save",
              pattern: "fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]...",
              source: "inline-script",
            },
          ],
        },
      ],
      allDiscoveredEndpoints: [
        "/api/stats",
        "/api/notes",
        "/api/settings/save",
      ],
      message:
        "Crawled 2 pages. Discovered 3 unique endpoints from JavaScript.",
    });
    expect(requests).toHaveLength(2);
  });

  it("extracts endpoints from the Authorization+Cookie authenticated body it already downloaded", async () => {
    // The authenticated view requires both the session config's Authorization
    // header and the caller's cookie. The crawler's resolver-merged request
    // carries both; a cookie-only refetch would see the anonymous page, so the
    // extracted endpoints prove the already-downloaded body is being reused.
    stubFetch((_url, headers) => ({
      status: 200,
      body:
        headerValue(headers, "cookie") === "sid=abc" &&
        headerValue(headers, "authorization") === "Bearer fixture-token"
          ? "<script>fetch('/api/authenticated');</script>"
          : "<script>fetch('/api/anon');</script>",
    }));

    const ctx = makeCtx({
      config: { headers: { Authorization: "Bearer fixture-token" } },
    });
    const result = (await crawlAuthenticated(ctx).execute?.(CRAWL_INPUT, {
      toolCallId: "tc_test",
      messages: [],
      abortSignal: undefined,
    })) as CrawlResult;

    expect(result.allDiscoveredEndpoints).toEqual(["/api/authenticated"]);
    expect(result.pages?.[0]?.jsEndpoints?.map((e) => e.endpoint)).toEqual([
      "/api/authenticated",
    ]);
  });

  it("skips error-status pages without endpoint extraction", async () => {
    const requests = stubFetch(() => ({ status: 500, body: "boom" }));

    const result = (await execute(CRAWL_INPUT)) as CrawlResult;

    expect(result.success).toBe(true);
    expect(result.totalPages).toBe(0);
    expect(result.message).toBe(
      "Crawled 1 pages. Discovered 0 unique endpoints from JavaScript.",
    );
    expect(requests).toHaveLength(1);
  });

  it("continues the crawl when a page request fails", async () => {
    const requests = stubFetch(() => {
      throw new Error("connection reset");
    });

    const result = (await execute(CRAWL_INPUT)) as CrawlResult;

    expect(result.success).toBe(true);
    expect(result.pagesVisited).toBe(1);
    expect(result.totalPages).toBe(0);
    expect(requests).toHaveLength(1);
  });

  it("rejects out-of-scope start URLs without any request", async () => {
    const requests = stubFetch(servePages({}));

    const result = (await execute({
      ...CRAWL_INPUT,
      startUrl: "https://evil.example.org/dashboard",
    })) as CrawlResult;

    expect(result.success).toBe(false);
    expect(result.message).toContain("Scope violation");
    expect(requests).toHaveLength(0);
  });
});
