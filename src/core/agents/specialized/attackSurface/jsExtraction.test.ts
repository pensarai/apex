import { afterEach, describe, expect, it, vi } from "vitest";
import type { HttpResponse } from "../../../tools/backends/types";
import type { ToolContext } from "../../offSecAgent/tools/types";
import {
  extractJavascriptEndpoints,
  extractJavascriptEndpointsFromHtml,
} from "./jsExtraction";

const PAGE_URL = "https://example.com/app";
const FETCH_PATTERN = "fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]...";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("extractJavascriptEndpointsFromHtml", () => {
  it("extracts endpoints across patterns in first-seen order with exact metadata", () => {
    const html = [
      "<html><head>",
      '<script src="/static/app.js"></script>',
      "<script>",
      "fetch('/api/users');",
      'url = "/api/users";',
      "fetch('/api/users');",
      "fetch(`/api/orders/123`);",
      "axios.get('/api/items/45');",
      'xhr.open("GET", "/api/session");',
      'action = "/api/submit";',
      "</script>",
      "</head><body></body></html>",
    ].join("\n");

    const result = extractJavascriptEndpointsFromHtml(html, PAGE_URL);

    // Scan order is per script tag, then per pattern family. The axios call
    // is matched by its first capture group (the method name), which the
    // root-relative check then filters out — current supported behavior.
    expect(result.totalAjaxCalls).toBe(6);
    expect(result.endpoints).toEqual([
      {
        endpoint: "/api/users",
        pattern: FETCH_PATTERN,
        source: "inline-script",
      },
      {
        endpoint: "/api/orders/123",
        pattern: "fetch\\s*\\(\\s*`([^`]+)`...",
        source: "inline-script",
      },
      {
        endpoint: "/api/session",
        pattern: "\\.open\\s*\\(\\s*['\"](?:GET|POST|...",
        source: "inline-script",
      },
      {
        endpoint: "/api/submit",
        pattern: "action\\s*[:=]\\s*['\"]([^'\"]+)['...",
        source: "inline-script",
      },
    ]);
    expect(result.externalJSFiles).toEqual(["/static/app.js"]);
    expect(result.filesAnalyzed).toBe(2);
    expect(result.success).toBe(true);
    expect(result.url).toBe(PAGE_URL);
    expect(result.message).toBe(
      "Found 4 unique endpoints in JavaScript (6 total calls).",
    );
  });

  it("keeps the first record's metadata and position for duplicates that differ", () => {
    const html = `<script>
      fetch('/api/first');
      fetch('/api/second');
      url = "/api/first";
      href = "/api/second";
    </script>`;

    const result = extractJavascriptEndpointsFromHtml(html, PAGE_URL);

    expect(result.totalAjaxCalls).toBe(4);
    expect(result.endpoints).toEqual([
      {
        endpoint: "/api/first",
        pattern: FETCH_PATTERN,
        source: "inline-script",
      },
      {
        endpoint: "/api/second",
        pattern: FETCH_PATTERN,
        source: "inline-script",
      },
    ]);
  });

  it("parameterizes numeric segments and dedupes the parameterized patterns", () => {
    const html = `<script>
      fetch('/api/items/123');
      fetch('/api/items/456');
      fetch('/api/items/123');
    </script>`;

    const result = extractJavascriptEndpointsFromHtml(html, PAGE_URL);

    expect(result.endpoints?.map((e) => e.endpoint)).toEqual([
      "/api/items/123",
      "/api/items/456",
    ]);
    expect(result.parameterizedPatterns).toEqual(["/api/items/{id}"]);
    expect(result.totalAjaxCalls).toBe(3);
  });

  it("collects external script sources only when requested", () => {
    const html = `<html><head>
      <script src="/static/app.js"></script>
      <script>fetch('/api/inline');</script>
    </head></html>`;

    const withExternal = extractJavascriptEndpointsFromHtml(html, PAGE_URL);
    const withoutExternal = extractJavascriptEndpointsFromHtml(
      html,
      PAGE_URL,
      false,
    );

    expect(withExternal.externalJSFiles).toEqual(["/static/app.js"]);
    expect(withExternal.filesAnalyzed).toBe(2);
    expect(withoutExternal.externalJSFiles).toEqual([]);
    expect(withoutExternal.filesAnalyzed).toBe(1);
    expect(withoutExternal.endpoints).toEqual(withExternal.endpoints);
  });

  it("ignores endpoints that are not root-relative paths", () => {
    const html = `<script>
      fetch('https://api.example.com/absolute');
      fetch('relative/path');
      fetch('/api/root-relative');
    </script>`;

    const result = extractJavascriptEndpointsFromHtml(html, PAGE_URL);

    expect(result.endpoints?.map((e) => e.endpoint)).toEqual([
      "/api/root-relative",
    ]);
  });

  it("parses typed and JSON script blocks like plain inline scripts", () => {
    const html = `<html><head>
      <script type="module">fetch('/api/module');</script>
      <script type="application/json">{url: "/api/data-block"}</script>
    </head></html>`;

    const result = extractJavascriptEndpointsFromHtml(html, PAGE_URL);

    expect(result.endpoints?.map((e) => e.endpoint)).toEqual([
      "/api/module",
      "/api/data-block",
    ]);
  });

  it("returns an empty success for pages with no script content", () => {
    const result = extractJavascriptEndpointsFromHtml(
      "<html><body><p>no scripts</p></body></html>",
      PAGE_URL,
    );

    expect(result.success).toBe(true);
    expect(result.endpoints).toEqual([]);
    expect(result.totalAjaxCalls).toBe(0);
    expect(result.message).toBe(
      "Found 0 unique endpoints in JavaScript (0 total calls).",
    );
  });
});

describe("extractJavascriptEndpoints (fetching helper)", () => {
  const html = `<script>fetch('/api/via-fetch');</script>`;

  // The page fetch routes through the tool http backend, never
  // a bare global fetch — so the test injects a fake backend on the context.
  function ctxWith(
    request: (...args: unknown[]) => Promise<HttpResponse>,
  ): ToolContext {
    return { backends: { http: { request } } } as unknown as ToolContext;
  }

  it("sends the session cookie as a Cookie header and matches the pure parser output", async () => {
    const request = vi.fn(
      async () => ({ success: true, body: html }) as HttpResponse,
    );

    const result = await extractJavascriptEndpoints({
      url: PAGE_URL,
      sessionCookie: "sid=abc",
      ctx: ctxWith(request),
    });

    expect(request).toHaveBeenCalledWith({
      url: PAGE_URL,
      method: "GET",
      headers: { Cookie: "sid=abc" },
    });
    expect(result).toEqual(extractJavascriptEndpointsFromHtml(html, PAGE_URL));
  });

  it("omits headers when no session cookie is given", async () => {
    const request = vi.fn(
      async () => ({ success: true, body: html }) as HttpResponse,
    );

    await extractJavascriptEndpoints({ url: PAGE_URL, ctx: ctxWith(request) });

    expect(request).toHaveBeenCalledWith({
      url: PAGE_URL,
      method: "GET",
      headers: undefined,
    });
  });

  it("returns a failure result when the page fetch fails", async () => {
    const request = vi.fn(
      async () =>
        ({ success: false, error: "connection refused" }) as HttpResponse,
    );

    const result = await extractJavascriptEndpoints({
      url: PAGE_URL,
      ctx: ctxWith(request),
    });

    expect(result.success).toBe(false);
    expect(result.message).toBe(
      "JavaScript extraction error: connection refused",
    );
  });
});
