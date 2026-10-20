import { afterEach, describe, expect, it, vi } from "vitest";
import { createTargetHeaderProvider } from "./targetHeaderProvider";
import {
  applyHeadersToShellCommandAsync,
  resolveEffectiveHeadersAsync,
  targetFetch,
} from "./targetHeaders";

const provider = {
  endpoint: "https://console.example/headers",
  token: "run-jwt",
};

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("target header refresh", () => {
  it("caches until expiry and coalesces simultaneous refreshes", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1000);
    const load = vi.fn(async () => ({
      headers: { Authorization: "Bearer first" },
      expiresAt: 2000,
    }));
    const resolve = createTargetHeaderProvider(provider, load);
    expect(await Promise.all([resolve(), resolve(), resolve()])).toEqual(
      Array(3).fill({ Authorization: "Bearer first" }),
    );
    expect(load).toHaveBeenCalledTimes(1);
    await resolve();
    expect(load).toHaveBeenCalledTimes(1);
    vi.setSystemTime(2000);
    load.mockResolvedValue({
      headers: { Authorization: "Bearer second" },
      expiresAt: 3000,
    });
    expect(await resolve()).toEqual({ Authorization: "Bearer second" });
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("does not use stale headers or disclose provider errors on refresh failure", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1000);
    const load = vi.fn(async () => ({
      headers: { Authorization: "Bearer first" },
      expiresAt: 2000,
    }));
    const resolve = createTargetHeaderProvider(provider, load);
    await resolve();
    vi.setSystemTime(2000);
    load.mockRejectedValue(new Error("secret-provider-response"));
    await expect(resolve()).rejects.toThrow(
      /^Target credential refresh failed$/,
    );
    load.mockResolvedValue({
      headers: { Authorization: "Bearer recovered" },
      expiresAt: 3000,
    });
    expect(await resolve()).toEqual({ Authorization: "Bearer recovered" });
  });

  it.each([
    { headers: {}, expiresAt: 0 },
    {
      headers: { Authorization: "bad\r\nInjected: yes" },
      expiresAt: Number.MAX_SAFE_INTEGER,
    },
    { headers: { "bad name": "value" }, expiresAt: Number.MAX_SAFE_INTEGER },
    { headers: { Authorization: 1 }, expiresAt: Number.MAX_SAFE_INTEGER },
  ])("rejects invalid provider snapshots", async (snapshot) => {
    await expect(
      createTargetHeaderProvider(provider, async () => snapshot)(),
    ).rejects.toThrow("Target credential refresh failed");
  });

  it("only calls the authenticated provider for scoped requests, preserving overrides", async () => {
    const fetch = vi.fn(async () =>
      Response.json({
        headers: { authorization: "Bearer current" },
        expiresAt: Number.MAX_SAFE_INTEGER,
      }),
    );
    vi.stubGlobal("fetch", fetch);
    const session = {
      targets: ["https://app.example.com"],
      config: {
        targetHeaderProvider: { ...provider },
        headers: { "X-Session": "session" },
      },
      credentialManager: {
        listCredentialsWithHeaders: () => [
          { tokens: { customHeaders: { Authorization: "Bearer stale" } } },
        ],
      },
    };
    expect(
      await resolveEffectiveHeadersAsync(
        session,
        "https://outside.example.net",
      ),
    ).toEqual({});
    expect(fetch).not.toHaveBeenCalled();
    expect(
      await resolveEffectiveHeadersAsync(session, "https://app.example.com"),
    ).toEqual({ "X-Session": "session", Authorization: "Bearer current" });
    expect(
      await resolveEffectiveHeadersAsync(session, "https://app.example.com", {
        AUTHORIZATION: "caller",
      }),
    ).toEqual({ "X-Session": "session", Authorization: "caller" });
    expect(fetch).toHaveBeenCalledWith(
      provider.endpoint,
      expect.objectContaining({
        method: "POST",
        redirect: "error",
        headers: { Authorization: "Bearer run-jwt" },
      }),
    );
    const shell = await applyHeadersToShellCommandAsync(
      "curl https://app.example.com",
      session,
      ["app.example.com"],
    );
    expect(shell.command).toContain("Bearer current");
    expect(shell.command).not.toContain("stale");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("never sends refreshed headers to an off-scope redirect", async () => {
    const fetch = vi.fn(async (url: string) => {
      if (url === provider.endpoint)
        return Response.json({
          headers: { Authorization: "Bearer current" },
          expiresAt: Number.MAX_SAFE_INTEGER,
        });
      if (url === "https://app.example.com/")
        return new Response(null, {
          status: 302,
          headers: { Location: "https://outside.example.net/" },
        });
      return new Response("ok");
    });
    vi.stubGlobal("fetch", fetch);
    await targetFetch(
      {
        targets: ["https://app.example.com"],
        config: { targetHeaderProvider: { ...provider } },
      },
      "https://app.example.com/",
    );
    expect(fetch).toHaveBeenLastCalledWith(
      "https://outside.example.net/",
      expect.objectContaining({ headers: {} }),
    );
  });

  it("refreshes again between redirect hops without treating old tokens as overrides", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1000);
    let refreshes = 0;
    const fetch = vi.fn(async (url: string) => {
      if (url === provider.endpoint) {
        refreshes++;
        return Response.json({
          headers: { Authorization: `Bearer ${refreshes}` },
          expiresAt: Date.now() + 1000,
        });
      }
      if (url === "https://app.example.com/first") {
        vi.setSystemTime(2000);
        return new Response(null, {
          status: 302,
          headers: { Location: "/second" },
        });
      }
      return new Response("ok");
    });
    vi.stubGlobal("fetch", fetch);
    const session = {
      targets: ["https://app.example.com"],
      config: { targetHeaderProvider: { ...provider } },
    };
    await targetFetch(session, "https://app.example.com/first");
    expect(fetch).toHaveBeenLastCalledWith(
      "https://app.example.com/second",
      expect.objectContaining({ headers: { Authorization: "Bearer 2" } }),
    );
    vi.setSystemTime(3000);
    const command = await applyHeadersToShellCommandAsync(
      "curl https://app.example.com",
      session,
      ["app.example.com"],
    );
    expect(command.command).toContain("Bearer 3");
    expect(refreshes).toBe(3);
  });

  it("aborts HTTP and shell execution when refresh fails", async () => {
    const fetch = vi.fn(async (_url: string) => {
      throw new Error("provider unavailable");
    });
    vi.stubGlobal("fetch", fetch);
    const session = {
      targets: ["https://app.example.com"],
      config: { targetHeaderProvider: { ...provider } },
    };
    await expect(
      targetFetch(session, "https://app.example.com"),
    ).rejects.toThrow("Target credential refresh failed");
    await expect(
      applyHeadersToShellCommandAsync("curl https://app.example.com", session, [
        "app.example.com",
      ]),
    ).rejects.toThrow("Target credential refresh failed");
    expect(fetch.mock.calls.every(([url]) => url === provider.endpoint)).toBe(
      true,
    );
  });
});
