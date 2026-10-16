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

    expect(policy.allowedHosts).toEqual(["app.example.com"]);
    expect(policy.allowedPorts).toEqual([]);
    expect(policy.enforceScope).toBe(true);
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
    ).toEqual({
      allowedHosts: [],
      allowedPorts: [],
      headers: {},
      enforceScope: false,
    });
  });

  it("snapshots the configured port allowlist", () => {
    expect(
      resolveBrowserHeaderPolicy({
        targets: ["https://app.example.com:8443"],
        config: {
          headers: { "X-Session-Secret": "secret" },
          scopeConstraints: {
            allowedHosts: ["app.example.com"],
            allowedPorts: [8443],
          },
        },
      }),
    ).toMatchObject({ allowedPorts: [8443] });
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
          fetch(options?: {
            headers?: Record<string, string>;
            maxRedirects?: number;
          }): Promise<unknown>;
          fulfill(options: { response: unknown }): Promise<void>;
          abort(code?: string): Promise<void>;
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
        allowedHosts: ["*.example.com"],
        allowedPorts: [443],
        headers: { "X-Scoped-Secret": "secret" },
        enforceScope: true,
      })})`,
      { URL },
    ) as (page: {
      context(): typeof context;
    }) => Promise<{ installed: boolean }>;

    await fn({ context: () => context });
    if (!handler) throw new Error("route handler was not installed");
    return handler;
  }

  it("fetches one scoped hop with headers, then fulfills the browser request", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});
    const fetchedResponse = {
      status: () => 200,
      headers: () => ({}),
    };
    const fetchRequest = vi.fn(async () => fetchedResponse);
    const fulfillRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://api.example.com/data",
        allHeaders: async () => ({
          ":authority": "api.example.com",
          accept: "application/json",
        }),
      }),
      continue: continueRequest,
      fetch: fetchRequest,
      fulfill: fulfillRequest,
      abort: vi.fn(),
    });

    expect(fetchRequest).toHaveBeenCalledWith({
      headers: {
        accept: "application/json",
        "X-Scoped-Secret": "secret",
      },
      maxRedirects: 0,
    });
    expect(fulfillRequest).toHaveBeenCalledWith({ response: fetchedResponse });
    expect(continueRequest).not.toHaveBeenCalled();
  });

  it("aborts out-of-scope requests when scope enforcement is active", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});
    const abortRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://outside.example.net/data",
        allHeaders: async () => ({ accept: "application/json" }),
      }),
      continue: continueRequest,
      fetch: vi.fn(),
      fulfill: vi.fn(),
      abort: abortRequest,
    });

    expect(abortRequest).toHaveBeenCalledWith("blockedbyclient");
    expect(continueRequest).not.toHaveBeenCalled();
  });

  it("uses the destination host rather than matching userinfo", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});
    const abortRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://api.example.com@outside.example.net/data",
        allHeaders: async () => ({ accept: "application/json" }),
      }),
      continue: continueRequest,
      fetch: vi.fn(),
      fulfill: vi.fn(),
      abort: abortRequest,
    });

    expect(abortRequest).toHaveBeenCalledWith("blockedbyclient");
    expect(continueRequest).not.toHaveBeenCalled();
  });

  it("does not inject headers on an unlisted port", async () => {
    const handler = await installRoute();
    const continueRequest = vi.fn(async () => {});
    const fetchRequest = vi.fn();
    const abortRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://api.example.com:8443/data",
        allHeaders: async () => ({ accept: "application/json" }),
      }),
      continue: continueRequest,
      fetch: fetchRequest,
      fulfill: vi.fn(),
      abort: abortRequest,
    });

    expect(abortRequest).toHaveBeenCalledWith("blockedbyclient");
    expect(continueRequest).not.toHaveBeenCalled();
    expect(fetchRequest).not.toHaveBeenCalled();
  });

  it("aborts a redirect response before the browser follows it", async () => {
    const handler = await installRoute();
    const abortRequest = vi.fn(async () => {});
    const fulfillRequest = vi.fn(async () => {});

    await handler({
      request: () => ({
        url: () => "https://api.example.com/start",
        allHeaders: async () => ({ accept: "text/html" }),
      }),
      continue: vi.fn(),
      fetch: vi.fn(async () => ({
        status: () => 302,
        headers: () => ({ location: "https://outside.example.net/final" }),
      })),
      fulfill: fulfillRequest,
      abort: abortRequest,
    });

    expect(abortRequest).toHaveBeenCalledWith("blockedbyclient");
    expect(fulfillRequest).not.toHaveBeenCalled();
  });
});
