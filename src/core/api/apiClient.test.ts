import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../auth", () => ({
  ensureValidToken: vi.fn(async () => ({ token: "tok" })),
}));
vi.mock("../config", () => ({
  config: { get: vi.fn(async () => ({ workspaceId: "ws-1" })) },
}));
vi.mock("./constants", () => ({
  getPensarApiUrl: () => "https://api.example.com",
}));
vi.mock("../installation", () => ({ getCurrentVersion: () => "1.4.2" }));

import { apiRequest } from "./apiClient";
import { CLIENT_HEADERS, setCurrentCommand } from "./clientIdentity";

function sentHeaders(): Record<string, string> {
  const call = vi.mocked(globalThis.fetch).mock.calls.at(-1);
  return (call?.[1] as { headers: Record<string, string> }).headers;
}

beforeEach(() => {
  setCurrentCommand(undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, text: async () => "{}" })),
  );
});

describe("apiRequest client identity", () => {
  // Console attributes a launch to whoever calls; without these headers every
  // caller of the public API looks the same and defaults to a generic client.
  it("identifies this client on every request", async () => {
    await apiRequest("GET", "/issues");

    expect(sentHeaders()).toMatchObject({
      [CLIENT_HEADERS.client]: "cli",
      [CLIENT_HEADERS.version]: "1.4.2",
    });
  });

  it("carries the command the router recorded", async () => {
    setCurrentCommand("pentests");
    await apiRequest("POST", "/pentests", {});

    expect(sentHeaders()[CLIENT_HEADERS.command]).toBe("pentests");
  });

  it("still sends auth and workspace headers", async () => {
    await apiRequest("GET", "/issues");

    expect(sentHeaders()).toMatchObject({
      Authorization: "Bearer tok",
      "X-Workspace-Id": "ws-1",
      "Content-Type": "application/json",
    });
  });
});
