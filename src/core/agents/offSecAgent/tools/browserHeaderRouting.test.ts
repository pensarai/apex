import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import {
  browserHeaderRouteFunction,
  resolveBrowserHeaderPolicy,
} from "./browserHeaderRouting";

describe("resolveBrowserHeaderPolicy", () => {
  it("snapshots session and credential headers for allowed hosts", () => {
    const policy = resolveBrowserHeaderPolicy(
      {
        targets: ["https://app.example.com"],
        config: {
          headers: {
            "X-Session-Secret": "session-secret",
            "User-Agent": "managed-elsewhere",
          },
        },
        credentialManager: {
          listCredentialsWithHeaders: () => [
            {
              tokens: {
                customHeaders: {
                  "X-Credential-Secret": "credential-secret",
                },
              },
            },
          ],
        },
      },
      "https://app.example.com",
    );

    expect(policy.allowedHosts).toEqual(["example.com"]);
    expect(policy.headers).toEqual({
      "X-Session-Secret": "session-secret",
      "X-Credential-Secret": "credential-secret",
    });
  });

  it("injects nothing when no target scope exists", () => {
    expect(
      resolveBrowserHeaderPolicy({
        config: { headers: { "X-Session-Secret": "secret" } },
      }),
    ).toEqual({ allowedHosts: [], headers: {} });
  });
});

describe("browserHeaderRouteFunction", () => {
  async function installRoute() {
    let handler:
      | ((route: {
          request(): {
            url(): string;
            allHeaders(): Promise<Record<string, string>>;
          };
          continue(options?: {
            headers?: Record<string, string>;
          }): Promise<void>;
        }) => Promise<void>)
      | undefined;
    const context = {
      route: vi.fn(
        async (_pattern: string, routeHandler: NonNullable<typeof handler>) => {
          handler = routeHandler;
        },
      ),
    };
    const fn = runInNewContext(
      `(${browserHeaderRouteFunction({
        allowedHosts: ["example.com"],
        headers: { "X-Scoped-Secret": "secret" },
      })})`,
    ) as (page: {
      context(): typeof context;
    }) => Promise<{ installed: boolean }>;

    await fn({ context: () => context });
    if (!handler) throw new Error("route handler was not installed");
    return handler;
  }

  it("merges scoped headers into in-scope requests", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://api.example.com/data",
        allHeaders: async () => ({
          ":authority": "api.example.com",
          accept: "application/json",
        }),
      }),
      continue: continueRequest,
    });

    expect(continueRequest).toHaveBeenCalledWith({
      headers: {
        accept: "application/json",
        "X-Scoped-Secret": "secret",
      },
    });
  });

  it("continues out-of-scope requests without injected headers", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://outside.example.net/data",
        allHeaders: async () => ({ accept: "application/json" }),
      }),
      continue: continueRequest,
    });

    expect(continueRequest).toHaveBeenCalledWith();
  });

  it("uses the destination host rather than matching userinfo", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://api.example.com@outside.example.net/data",
        allHeaders: async () => ({ accept: "application/json" }),
      }),
      continue: continueRequest,
    });

    expect(continueRequest).toHaveBeenCalledWith();
  });
});

describe("browser per-request credential refresh", () => {
  it("refreshes a persistent context, coalesces requests, and fails closed", async () => {
    let now = 1000;
    const post = vi.fn(async () => ({
      ok: () => true,
      text: async () =>
        JSON.stringify({
          headers: {
            authorization: now < 2000 ? "Bearer first" : "Bearer second",
          },
          expiresAt: now + 1000,
        }),
      dispose: vi.fn(),
    }));
    let handler: (route: unknown) => Promise<void> = async () => {
      throw new Error("not installed");
    };
    const context = {
      request: { post },
      route: async (_pattern: string, callback: typeof handler) => {
        handler = callback;
      },
    };
    const install = runInNewContext(
      `(${browserHeaderRouteFunction({
        allowedHosts: ["example.com"],
        headers: { Authorization: "Bearer stale" },
        targetHeaderProvider: {
          endpoint: "https://console.example/headers",
          token: "run-jwt",
        },
      })})`,
      { Date: { now: () => now } },
    );
    await install({ context: () => context });
    const route = (url = "https://app.example.com") => ({
      request: () => ({
        url: () => url,
        allHeaders: async () => ({
          authorization: "Bearer stale",
          cookie: "session=browser",
        }),
      }),
      fetch: vi.fn(async () => ({ status: 200, dispose: vi.fn() })),
      fulfill: vi.fn(),
      continue: vi.fn(),
      abort: vi.fn(),
    });
    const first = route();
    const parallel = route();
    await Promise.all([handler(first), handler(parallel)]);
    expect(post).toHaveBeenCalledTimes(1);
    expect(first.fetch).toHaveBeenCalledWith({
      headers: { authorization: "Bearer first", cookie: "session=browser" },
      maxRedirects: 0,
    });
    now = 2000;
    const second = route();
    await handler(second);
    expect(post).toHaveBeenCalledTimes(2);
    expect(second.fetch).toHaveBeenCalledWith({
      headers: { authorization: "Bearer second", cookie: "session=browser" },
      maxRedirects: 0,
    });
    const outside = route("https://outside.example.net");
    await handler(outside);
    expect(post).toHaveBeenCalledTimes(2);
    expect(outside.continue).toHaveBeenCalledWith({
      headers: { cookie: "session=browser" },
    });
    expect(outside.fetch).not.toHaveBeenCalled();
    now = 3000;
    post.mockRejectedValue(new Error("provider-secret"));
    const failed = route();
    await handler(failed);
    expect(failed.abort).toHaveBeenCalledWith("failed");
    expect(failed.fetch).not.toHaveBeenCalled();
    expect(failed.continue).not.toHaveBeenCalled();
  });
});
