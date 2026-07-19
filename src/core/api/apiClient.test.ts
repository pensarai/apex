import { afterEach, describe, expect, it, vi } from "vitest";

const { ensureValidToken, getConfig } = vi.hoisted(() => ({
  ensureValidToken: vi.fn(),
  getConfig: vi.fn(async () => ({
    workosSession: true,
    workspaceId: "workspace-1",
  })),
}));

vi.mock("../auth", () => ({ ensureValidToken }));
vi.mock("../config", () => ({ config: { get: getConfig } }));
vi.mock("./constants", () => ({
  getPensarApiUrl: () => "https://console.example.com",
}));

import { apiRequest } from "./apiClient";

describe("apiRequest authentication", () => {
  afterEach(() => {
    ensureValidToken.mockReset();
    getConfig.mockClear();
    vi.unstubAllGlobals();
  });

  it("refreshes and retries once after a WorkOS token is rejected", async () => {
    ensureValidToken
      .mockResolvedValueOnce({ token: "rejected-token", type: "workos" })
      .mockResolvedValueOnce({ token: "fresh-token", type: "workos" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("unauthorized", { status: 401 }))
      .mockResolvedValueOnce(Response.json({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest("GET", "/resource")).resolves.toEqual({
      ok: true,
    });

    expect(ensureValidToken).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ workosSession: true }),
      { forceRefresh: true, rejectedToken: "rejected-token" },
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[1]?.headers).toMatchObject({
      Authorization: "Bearer fresh-token",
      "X-Workspace-Id": "workspace-1",
    });
  });

  it("does not refresh or retry rejected legacy credentials", async () => {
    ensureValidToken.mockResolvedValue({
      token: "legacy-token",
      type: "legacy",
    });
    const fetchMock = vi.fn(
      async () => new Response("unauthorized", { status: 401 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest("GET", "/resource")).rejects.toThrow(
      "API error (401)",
    );
    expect(ensureValidToken).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
