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
    const fn = new Function(
      `return (${browserHeaderRouteFunction({
        allowedHosts: ["example.com"],
        headers: { "X-Scoped-Secret": "secret" },
      })})`,
    )() as (page: {
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
        allHeaders: async () => ({ accept: "application/json" }),
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
});
