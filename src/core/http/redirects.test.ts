import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchWithScopedRedirects,
  MAX_TARGET_REDIRECTS,
  redirectRequest,
  sanitizeRedirectHeaders,
} from "./redirects";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("redirectRequest", () => {
  it.each([
    [301, "POST"],
    [302, "POST"],
    [303, "POST"],
    [303, "PATCH"],
  ])("rewrites %s %s to GET without a body", (status, method) => {
    expect(redirectRequest(status, method, "payload")).toEqual({
      method: "GET",
      body: undefined,
      bodyDropped: true,
    });
  });

  it.each([
    [301, "PUT"],
    [302, "PATCH"],
    [303, "HEAD"],
    [307, "POST"],
    [308, "PATCH"],
  ])("preserves %s %s", (status, method) => {
    expect(redirectRequest(status, method, "payload")).toEqual({
      method,
      body: "payload",
      bodyDropped: false,
    });
  });
});

describe("sanitizeRedirectHeaders", () => {
  it("drops standard credentials after crossing origins", () => {
    expect(
      sanitizeRedirectHeaders(
        {
          Authorization: "secret",
          Cookie: "sid=secret",
          "X-Scoped-Key": "keep",
        },
        { crossOriginTainted: true, bodyDropped: false },
      ),
    ).toEqual({ "X-Scoped-Key": "keep" });
  });

  it("drops body headers after redirect method rewriting", () => {
    expect(
      sanitizeRedirectHeaders(
        {
          "Content-Type": "application/json",
          "Content-Length": "2",
          Accept: "application/json",
        },
        { crossOriginTainted: false, bodyDropped: true },
      ),
    ).toEqual({ Accept: "application/json" });
  });
});

describe("fetchWithScopedRedirects", () => {
  it("follows relative redirects and exposes the full chain", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response("", { status: 302, headers: { Location: "/next" } }),
      )
      .mockResolvedValueOnce(new Response("done", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await fetchWithScopedRedirects(
      "https://example.com/start",
      { method: "GET", redirect: "follow" },
      () => ({ "X-Test": "value" }),
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://example.com/start",
      "https://example.com/next",
    ]);
    expect(result.redirectChain).toEqual([
      "https://example.com/start",
      "https://example.com/next",
    ]);
    expect(await result.response.text()).toBe("done");
  });

  it("keeps a manual redirect as the final response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("", {
        status: 302,
        headers: { Location: "https://other.example/next" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await fetchWithScopedRedirects(
      "https://example.com/start",
      { redirect: "manual" },
      () => ({}),
    );

    expect(result.response.status).toBe(302);
    expect(result.redirectChain).toEqual(["https://example.com/start"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rewrites POST on 302 and removes body headers", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response("", { status: 302, headers: { Location: "/done" } }),
      )
      .mockResolvedValueOnce(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await fetchWithScopedRedirects(
      "https://example.com/start",
      {
        method: "POST",
        body: "payload",
        redirect: "follow",
      },
      () => ({
        "Content-Type": "text/plain",
        "Content-Length": "7",
        Accept: "text/plain",
      }),
    );

    const secondInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(secondInit).toMatchObject({ method: "GET", body: undefined });
    expect(secondInit.headers).toEqual({ Accept: "text/plain" });
  });

  it("marks every later hop as cross-origin tainted", async () => {
    const contexts: boolean[] = [];
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response("", {
          status: 302,
          headers: { Location: "https://other.example/one" },
        }),
      )
      .mockResolvedValueOnce(
        new Response("", { status: 302, headers: { Location: "/two" } }),
      )
      .mockResolvedValueOnce(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await fetchWithScopedRedirects(
      "https://example.com/start",
      { redirect: "follow" },
      (_url, context) => {
        contexts.push(context.crossOriginTainted);
        return {};
      },
    );

    expect(contexts).toEqual([false, true, true]);
  });

  it("rejects unsupported redirect protocols", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("", {
          status: 302,
          headers: { Location: "file:///tmp/secret" },
        }),
      ),
    );

    await expect(
      fetchWithScopedRedirects(
        "https://example.com/start",
        { redirect: "follow" },
        () => ({}),
      ),
    ).rejects.toThrow("Unsupported redirect protocol");
  });

  it("fails after the Fetch-compatible redirect limit", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("", {
        status: 302,
        headers: { Location: "/loop" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchWithScopedRedirects(
        "https://example.com/start",
        { redirect: "follow" },
        () => ({}),
      ),
    ).rejects.toThrow(
      `Maximum redirect count exceeded (${MAX_TARGET_REDIRECTS})`,
    );
    expect(fetchMock).toHaveBeenCalledTimes(MAX_TARGET_REDIRECTS + 1);
  });
});
